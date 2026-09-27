// DeltaHack — runtime PE-header sanitizer.
//
// Обнуляет DOS-заголовок и NT-signature собственного модуля СРАЗУ после старта.
// Файл на диске остаётся с валидным "MZ..PE"; в памяти сигнатуры превращаются
// в мусор.
//
// Что убивает:
//   • Memory-scan по паттерну "MZ" (0x5A4D) в RWX-регионах у процесса
//   • Memory-scan по "PE\0\0" (0x00004550) на IMAGE_NT_HEADERS
//   • Dump-recover через ReClass/PE-bear/Scylla: без валидного header
//     дампалка не восстановит sections layout → дамп бесполезен
//
// Чего НЕ убивает:
//   • On-disk scan (AV-signature на файле dh_loader.exe): для этого нужен
//     KFPL-wrap через отдельный launcher (см. launcher/dh_launcher.c)
//   • Behavior-based detection: SCM install, driver load, RPM syscalls —
//     всё живёт своей жизнью, MZ wipe их не трогает
//
// Safety:
//   • Ни один Windows API не читает IMAGE_DOS_HEADER после того как loader
//     завершил map+relocate+import fixup. Мы стёрли ТОЛЬКО заголовки,
//     секции нетронуты.
//   • x64 unwind (RtlAddFunctionTable) не смотрит DOS/NT header — он
//     видит IMAGE_RUNTIME_FUNCTION_ENTRY в .pdata по адресу который
//     передан при инсталляции.
#pragma once

// Zeroes IMAGE_DOS_HEADER + IMAGE_NT_HEADERS64 (headers only) of the
// currently-loaded module. Called ONCE at very early main.
//
// Returns 1 on success, 0 if wipe skipped (VirtualProtect failed etc.).
int DhWipeOwnPeHeaders(void);
