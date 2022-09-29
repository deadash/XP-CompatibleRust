use std::{fs, collections::HashMap, rc::Rc};
use goblin::pe::PE;
use goblin::pe::import::ImportDirectoryEntry;
use include_dir::{include_dir, Dir};
use anyhow::Result;
use scroll::{Pwrite, Pread};

static PROJECT_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/modules");

fn get_funcname(name: &str) -> String
{
    return (&name[0 .. (&name[1 .. ]).find(" ").unwrap_or(name.len() - 1) + 1]).to_owned()
}

// 具体思路：
// 1.修复系统版本到 0501
// 2.导入表修复
//    1. kernel32、以及其他 合并到 xpstub.dll 模块
//    2. 如有模块导入函数多余则保留，否则删除
//    3. xpstub模块拥有所有kernel32导入以及其他模块部分
//    4. IAT表进行整理并计算最后地空间，进行修改节或者移动

// TODO:优化
// IAT目录表 -> INT,NAME,FUNCTION 三块区域
// 通过地址融合，得到区域位置以及大小，然后再行分配
// FIXME: 目前 dll名称和函数名称混合在一起可能会计算错误.

#[derive(Debug, Default)]
struct IAT<'a>
{
    pub name: String,   // 函数名称
    pub dll: &'a str,   // dll模块名称
    pub ordinal: u16,   // 序号
    pub offset: usize,  // (原) 导入表函数地址
    pub rva: usize,     // 名称地址
}

fn _in_blacklist(dll: &str) -> bool
{
    ["bcrypt.dll"].contains(&dll)
}

const XPSTUB: &str = "xpstub.dll";

fn foa(pe: &PE, rva: u32) -> usize
{
    for sec in &pe.sections {
        if rva >= sec.virtual_address && rva <= (sec.virtual_address + sec.size_of_raw_data) {
            return (rva - sec.virtual_address + sec.pointer_to_raw_data) as usize;
        }
    }
    0usize
}

fn main() -> Result<()> {
    // 加载配置文件
    let mut tables: HashMap<String, Vec<String>> = HashMap::new();
    for file in PROJECT_DIR.files() {
        let name = file.path().file_name().unwrap_or_default().to_str().unwrap().replace(".txt", ".dll");
        let content = file.contents_utf8().unwrap();
        let mut funcs: Vec<String> = Vec::new();
        for line in content.lines() {
            let func = get_funcname(line);
            funcs.push(func);
        }
        tables.insert(name, funcs);
    }
    // 读取目标文件
    let buffer = fs::read("D:\\Projects\\刷卡项目\\code\\target\\i686-pc-windows-msvc\\release\\netCardCtrlSrv.exe")?;
    let pe = PE::parse(&buffer)?;
    // 重构新的IAT
    let mut new_iat = Vec::new();
    // 保存名称的起始地址
    let mut name_start = 0usize;
    let mut name_end = 0usize;
    // 保存函数的起始地址
    let mut func_start = 0usize;
    let mut func_end = 0usize;
    for ref imp in &pe.imports {
        let dll = imp.dll.to_lowercase();
        // 查找保存字符串的开头地方
        if name_start > imp.rva || name_start == 0 {
            name_start = imp.rva;
        }
        if name_end <= imp.rva {
            name_end = imp.rva + 2 + imp.name.len() + 1;
        }
        if func_start > imp.offset || func_start == 0 {
            func_start = imp.offset;
        }
        if func_end <= imp.offset {
            func_end = imp.offset + 4;
        }
        let name = imp.name.to_string();
        let is_ker32 = imp.dll.to_lowercase() == "kernel32.dll";
        let new_dll = if let Some(exists) = tables.get(&dll) {
            // 强制使用kernel32模块, 以免没有空间使用 (如果有多的也可以考虑不转发)
            if !is_ker32 && exists.contains(&name) {
                imp.dll
            }
            else {
                XPSTUB
            }
        } else {
            imp.dll
        };
        new_iat.push(Rc::new(IAT { name, dll: new_dll, ordinal: imp.ordinal, offset: imp.offset, rva: imp.rva, .. Default::default() }))
    }
    // 按新的顺序生成新的IAT表
    let mut out = buffer.to_vec();
    // 获取导入目录
    let imp_dir = pe.header.optional_header.unwrap().data_directories.get_import_table().unwrap();
    let mut start = foa(&pe, imp_dir.virtual_address);
    // 按照dll模块进行划分
    let mut new_iat_desc: HashMap<String, Vec<Rc<IAT>>> = HashMap::new();
    for iat in &new_iat {
        let dll = iat.dll;
        let niat = iat.clone();
        if let Some(riat) = new_iat_desc.get_mut(dll) {
            riat.push(niat);
        } else {
            new_iat_desc.insert(dll.to_string(), vec![niat]);
        }
    }
    // 按导入目录排列所有的函数
    let mut name_offset = name_start;
    let mut func_offset = func_start;
    // 新的函数表，旧地址 -> 新地址 (函数地址)
    let mut new_offset = HashMap::new();
    // 新的 name
    let mut new_name = HashMap::new();
    // 新的 firstthunk
    let mut new_thunk = HashMap::new();
    // 新的INT 偏移
    let mut new_int = Vec::new();
    let mut new_origin = HashMap::new();
    // INT 表是文件偏移地址
    let image_base = pe.image_base;
    for iat_sec in &new_iat_desc {
        let dll = iat_sec.0;
        new_name.insert(dll.to_owned(), name_offset);
        new_thunk.insert(dll.to_owned(), func_offset);
        new_origin.insert(dll.to_owned(), new_int.len() * 4);
        name_offset += dll.len() + 1;
        for int in iat_sec.1 {
            // 内存加载以基地址为准, 这里应该加上基地址
            new_offset.insert(int.offset + image_base, func_offset + image_base);
            func_offset += 4usize;
            new_int.push(name_offset);
            if int.rva == 0 {
                name_offset += 2;
            } else {
                name_offset += 2 + int.name.len() + 1;
            }
        }
        new_int.push(0);
        // MAYBE: 留空, 去掉可不留
        func_offset += 4usize;
    }
    if func_offset > func_end + 4 {
        println!("+ Not enough function addresses to write. {:x} - {:x}, {:x}", func_start, func_end, func_offset);
    }
    // 获取INT 基地址
    let mut int_base = 0usize;
    for ints in &pe.import_data.as_ref().unwrap().import_data {
        let int = &ints.import_directory_entry;
        if int_base > int.import_lookup_table_rva as usize || int_base == 0 {
            int_base = int.import_lookup_table_rva as usize;
        }
        // TODO: 默认都是0, 旧版本为-1
        if int.time_date_stamp != 0 || int.forwarder_chain != 0 {
            println!("+ Unsupported INT model in {}, {:x?}", ints.name, int);
        }
    }
    // 写入到 out
    const LE: scroll::Endian = scroll::LE;
    // 先写入IAT目录
    for iat in &new_iat_desc {
        let name = iat.0;
        let import_lookup_table_rva = (new_origin[name] + int_base) as u32;
        let name_rva = new_name[name] as u32;
        let import_address_table_rva = new_thunk[name] as u32;
        out.gwrite_with(ImportDirectoryEntry { import_lookup_table_rva, time_date_stamp: 0, forwarder_chain: 0, name_rva, import_address_table_rva }, &mut start, LE)?;
    }
    out.gwrite_with(ImportDirectoryEntry { import_lookup_table_rva: 0, time_date_stamp: 0, forwarder_chain: 0, name_rva: 0, import_address_table_rva: 0 }, &mut start, LE)?;
    // 再写入INT 表
    let mut p_int = foa(&pe, int_base as u32);
    for int in new_int {
        out.gwrite_with::<u32>(int as u32, &mut p_int, LE)?;
    }
    // 写入字符串
    let mut p_name = foa(&pe, name_start as u32);
    for iat_sec in &new_iat_desc {
        let dll = iat_sec.0;
        println!("write name: {}", dll);
        out.gwrite_with::<&str>(dll, &mut p_name, ())?;
        out.gwrite_with::<u8>(0, &mut p_name, LE)?;
        for int in iat_sec.1 {
            // OrdinalNumber
            if int.rva == 0 {
                // TODO: 暂时不支持
                out.gwrite_with::<u16>(int.ordinal | 0x8000u16, &mut p_name, LE)?;
            // HintNameTableRVA
            } else {
                out.gwrite_with::<u16>(int.ordinal, &mut p_name, LE)?;
                out.gwrite_with::<&str>(&int.name, &mut p_name, ())?;
                out.gwrite_with::<u8>(0, &mut p_name, LE)?;
            }
        }
    }
    let mut matches = Vec::new();
    // 通过重定位表来获取所有定位地址
    if let Some(reloc) = pe.header.optional_header.unwrap().data_directories.get_base_relocation_table() {
        let base = foa(&pe, reloc.virtual_address);
        let reloc_buff = &buffer[base .. base + reloc.size as usize];
        let mut offset = 0usize;
        loop {
            let va:u32 = reloc_buff.gread_with(&mut offset, LE)?;
            // MAYBE: break if va == 0;
            let size:u32 = reloc_buff.gread_with(&mut offset, LE)?;
            let block = ((size - 8) / 2) as usize;
            // 可以预先计算偏移基地址
            let base = foa(&pe, va);
            for _ in 0 .. block {
                let p:u16 = reloc_buff.gread_with(&mut offset, LE)?;
                let of = (p & 0xfff) as usize;
                let addr = (base + of) as usize;
                matches.push(addr);
            }
            if offset >= reloc.size as usize {
                break;
            }
        }
    } else {
        // TODO: 以下并不会生效
        // 通过ff15/ff25搜索, 找到所有函数引用处 (部分move 啥的没有处理)
        // 按节搜索
        for sec in pe.sections {
            // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags
            if sec.characteristics & (0x00000020 | 0x20000000) == 0 {
                continue;
            }
            let base = sec.pointer_to_raw_data as usize;
            let size = std::cmp::min(sec.virtual_size, sec.size_of_raw_data) as usize;
            let buffer = &buffer[base .. base + size];
            let mut iter = buffer.windows(2);
            let pattern = |x: &[u8]| -> bool {
                x[0] == 0xff && ( x[1] == 0x15 || x[1] == 0x25 )
            };
            loop {
                let val = iter.position(pattern);
                if val.is_none() {
                    break;
                }
                let val = val.unwrap();
                match matches.last() {
                    Some(&last_val) => matches.push(base + 2 +val + last_val + 0x1),
                    None => matches.push(base + 2 + val),
                };
            }
        }
    }

    for addr in matches {
        let p: u32 = buffer.pread_with(addr, LE)?;
        let p = p as usize;
        if let Some(n) = new_offset.get(&p) {
            let patch = *n as u32;
            out.pwrite_with::<u32>(patch, addr, LE)?;
        }
    }

    // 修复相关的函数引用
    fs::write("D:\\Projects\\xpstub\\makexpstub\\test.exe", out)?;
    Ok(())
}