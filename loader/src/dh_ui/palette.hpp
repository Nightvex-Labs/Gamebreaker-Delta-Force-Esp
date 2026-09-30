// palette.hpp — ЕДИНСТВЕННЫЙ источник цветов Nightvex.
//
// Правило: нигде больше не писать IM_COL32(...) с сырыми числами и не заводить
// локальные C_AMBER / col_green / col_purple. Всё берётся отсюда.
// Значения — из ТЗ (TZ-Visuals-Players §3, TZ-Radar §8, TZ-Top-Loot §6,
// TZ-Overlay-HUD §2-4, TZ-Ammo-Counter §2/§4, TZ-Modal §6.4).
//
// ВСЁ constexpr намеренно. Раньше константы были inline const с вызовом
// НЕ-constexpr rgb(), то есть инициализировались динамически; порядок
// динамической инициализации inline-переменных между единицами трансляции не
// определён, а тут одни константы ссылаются на другие (radar::PMC = esp::TEAM,
// radar::LOOT = ARMOR_TIER[3], ammo::OK = esp::AMMO). Достаточно одной сборки
// с «неудачным» порядком, чтобы половина оверлея стала прозрачно-чёрной.
// constexpr переводит всё в constant-initialization и снимает вопрос.

#pragma once
#include <imgui.h>
#include <cstdint>

namespace abi::pal {

// a — доля 0..1; округление то же, что было в коде: (int)(a*255 + 0.5).
constexpr ImU32 rgb(unsigned hex, float a = 1.0f) {
    return IM_COL32((hex >> 16) & 0xFF, (hex >> 8) & 0xFF, hex & 0xFF,
                    (int)(a * 255.0f + 0.5f));
}
// Вариант с альфой ровно в 0..255 — для мест, где ТЗ задаёт байт, а не долю.
constexpr ImU32 rgb8(unsigned hex, int a) {
    return IM_COL32((hex >> 16) & 0xFF, (hex >> 8) & 0xFF, hex & 0xFF, a);
}
constexpr ImU32 wht(float a) { return IM_COL32(255, 255, 255, (int)(a * 255.0f + 0.5f)); }
constexpr ImU32 blk(float a) { return IM_COL32(0, 0, 0, (int)(a * 255.0f + 0.5f)); }
constexpr ImU32 alpha(ImU32 c, float a) {
    return (c & 0x00FFFFFFu) | ((ImU32)(a * 255.0f + 0.5f) << IM_COL32_A_SHIFT);
}

// ══════════════════════════════════════════════════════════════════════════
//  GAMEBREAKER control-panel exact palette (HOST_PATCH.md §1).
//  control_panel.cpp reads ONLY from abi::pal::gb; do not edit numbers here
//  unless the mock changes.
// ══════════════════════════════════════════════════════════════════════════
namespace gb {
// Тема «Dark · Peach» (фон как у gamebreaker.ru — #1C1E2C)
// поверхности
constexpr ImU32 WINDOW      = rgb(0x1C1E2C);        // фон окна
constexpr ImU32 BAR         = rgb(0x24273A);        // шапка, сайдбар
constexpr ImU32 CARD        = rgb(0x24273A);        // строки
constexpr ImU32 PANEL       = rgb(0x2A2D42);        // раскрытые панели, 44px-блоки, hover строк
constexpr ImU32 CHIP        = rgb(0x33374D);        // радио, поля, активный пункт меню
constexpr ImU32 CHIP_ON     = rgb(0xF5997C);        // активная пилюля / блок / кольцо радио
constexpr ImU32 LOGO_TILE   = rgb(0x2F3244);        // = подложка RU/EN поверх BAR
constexpr ImU32 LINE        = rgb(0x30344A);        // обводка 44px-блоков
constexpr ImU32 TRACK       = rgb(0x363A50);        // дорожка ползунка, декор-заголовок
constexpr ImU32 SEG_BG      = rgb(0xFFFFFF, 0.05f); // подложка сегмент-переключателя
// текст
constexpr ImU32 TEXT        = rgb(0xEEF0F7);
constexpr ImU32 TEXT_MUTED  = rgb(0x8E93AB);
constexpr ImU32 TEXT_DIM    = rgb(0x7D839E);
constexpr ImU32 TEXT_FAINT  = rgb(0x737995);        // микро-капс HEX
constexpr ImU32 WHITE       = rgb(0xFFFFFF);
constexpr ImU32 ON_ACCENT   = rgb(0x1C1E2C);        // текст на персиковой пилюле
constexpr ImU32 KNOB        = rgb(0xF4F5FA);        // ручки ползунков
// акцент
constexpr ImU32 ACCENT      = rgb(0xF5997C);
constexpr ImU32 SELECTION   = rgb(0xF5997C, 0.22f);
// мелочи
constexpr ImU32 SWATCH_LINE = rgb(0xFFFFFF, 0.14f);
constexpr ImU32 KNOB_SHADOW = rgb(0x000000, 0.35f);
constexpr ImU32 SCROLL      = rgb(0xFFFFFF, 0.16f);
constexpr ImU32 SCROLL_HOT  = rgb(0xFFFFFF, 0.32f);
constexpr ImU32 CH_R        = rgb(0xD4685F);
constexpr ImU32 CH_G        = rgb(0x5F9E77);
constexpr ImU32 CH_B        = rgb(0x6F9FE8);
// ESP по умолчанию
constexpr ImU32 ESP_BOX     = rgb(0xE5534B);
constexpr ImU32 ESP_NAME    = rgb(0x45A3D8);
constexpr ImU32 ESP_TEXT    = rgb(0xE6E2DA);        // weapon / ammo / distance ботов
constexpr ImU32 ESP_DIST    = rgb(0x4DBD78);
constexpr ImU32 ESP_CORPSE  = rgb(0x9AA1A7);
// палитра выбора цвета ESP (24)
constexpr ImU32 ESP_PAL[24] = {
    rgb(0xE5534B), rgb(0xE8684A), rgb(0xEB7F45), rgb(0xEE9A3F), rgb(0xE9B23C), rgb(0xE3C940),
    rgb(0xC4D24A), rgb(0x9BCB52), rgb(0x6FC45E), rgb(0x4DBD78), rgb(0x3FB894), rgb(0x3BB5AC),
    rgb(0x3BB0C4), rgb(0x45A3D8), rgb(0x5690E0), rgb(0x6A7DE3), rgb(0x7F6CE0), rgb(0x9660D9),
    rgb(0xAE58CF), rgb(0xC653BE), rgb(0xD6509F), rgb(0xDE5082), rgb(0xE6E2DA), rgb(0x9AA1A7),
};
} // namespace gb

// ══════════════════════════════════════════════════════════════════════════
//  menu_v3 tokens (Spectra v3 Dark mockup). Re-uses gb::WINDOW/CARD/PANEL/
//  CHIP/LOGO_TILE/TRACK/SEG_BG/TEXT*/ON_ACCENT/KNOB/KNOB_SHADOW/ACCENT/
//  SWATCH_LINE/SCROLL* as the base; adds only the roles the new design
//  needed on top of the existing palette.
namespace gb3 {
constexpr ImU32 WINDOW_GLASS = rgb(0x1C1E2C);        // фон окна: полностью непрозрачный
constexpr ImU32 GLASS      = rgb(0xFFFFFF, 0.035f);  // полупрозрачные плашки
constexpr ImU32 GLASS_HOT  = rgb(0xFFFFFF, 0.065f);  // hover / раскрытые панели
constexpr ImU32 GLASS_ON   = rgb(0xFFFFFF, 0.09f);   // активный таб Игроки/Боты
constexpr ImU32 GLASS_LINE = rgb(0xFFC4B0, 0.10f);   // тонкая тёплая обводка плашек
constexpr ImU32 OFF_DOT    = rgb(0x4A4F68);   // кольцо выключенной строки
constexpr ImU32 ESP_BOX    = rgb(0xE5534B);
constexpr ImU32 NAME_PMC   = rgb(0x45A3D8);
constexpr ImU32 NAME_BOT   = rgb(0x8B9CFF);
constexpr ImU32 ESP_TEXT   = rgb(0xE6E2DA);
constexpr ImU32 ESP_DIST   = rgb(0x4DBD78);
constexpr ImU32 ESP_CORPSE = rgb(0x8E93AB);
constexpr ImU32 TEAM       = rgb(0xD4527A);
constexpr ImU32 HP         = rgb(0x4BBF8A);
constexpr ImU32 ARMOR_H    = rgb(0xC7A05C);
constexpr ImU32 ARMOR_V    = rgb(0xB06060);
constexpr ImU32 SWATCH[12] = {
    rgb(0xE5534B), rgb(0xF5997C), rgb(0xE6A35A), rgb(0xE6D25A), rgb(0x4DBD78), rgb(0x45A3D8),
    rgb(0x6F9FE8), rgb(0x8B9CFF), rgb(0xC77DDB), rgb(0xD4527A), rgb(0xE6E2DA), rgb(0x8E93AB),
};
} // namespace gb3


// ══════════════════════════════════════════════════════════════════════════
//  БАЗОВЫЕ ТОКЕНЫ Fey — 1:1 с frontend/src/styles/global.css админки.
//  Это единственный слой, где вообще появляются hex-числа интерфейса.
//  Всё ниже — только имена ролей поверх этих токенов.
// ══════════════════════════════════════════════════════════════════════════
constexpr ImU32 BG      = rgb(0x08080A);   // --bg      грунт приложения
constexpr ImU32 BG_DEEP = rgb(0x060608);   // --bg-deep утопленное: треки, инсеты
constexpr ImU32 S1      = rgb(0x0E0E11);   // --s1      карточки
constexpr ImU32 S2      = rgb(0x141418);   // --s2      hover, вложенное
constexpr ImU32 S3      = rgb(0x1A1A1F);   // --s3      активное, контролы
constexpr ImU32 HAIR    = wht(0.07f);      // --hair
constexpr ImU32 HAIR2   = wht(0.11f);      // --hair2
constexpr ImU32 T1      = rgb(0xF4F4F6);   // --t1
constexpr ImU32 T2      = rgb(0x8B8B95);   // --t2
constexpr ImU32 T3      = rgb(0x56565F);   // --t3
constexpr ImU32 T4      = rgb(0x393940);   // --t4
constexpr ImU32 POS     = rgb(0x4BBF8A);   // --pos
constexpr ImU32 NEG     = rgb(0xE2574D);   // --neg
constexpr ImU32 AMBER   = rgb(0xE6A35A);   // --amber
constexpr ImU32 AMBER_2 = rgb(0xB06B34);   // --amber-2 (тёмный стоп градиента)
constexpr ImU32 BRAND   = rgb(0xE86A3A);   // --brand
constexpr ImU32 FOCUS   = rgb(0x5A93E0);   // --focus
constexpr ImU32 GRID    = wht(0.05f);      // --grid
// Полупрозрачные заливки семантики: строго .12, как pos-bg / neg-bg в CSS.
constexpr float TINT    = 0.12f;

// ── Роли поверхностей (панель) ─────────────────────────────────────────────
constexpr ImU32 DESKTOP     = BG_DEEP;   // фон превью-хоста
constexpr ImU32 WINDOW      = BG;
// Сайдбар намеренно делит фон с окном: отдельная заливка заставляла две
// половины панели читаться как разные поверхности. Алиас, а не свой цвет.
constexpr ImU32 SIDEBAR     = BG;
constexpr ImU32 CARD        = S1;
constexpr ImU32 CARD_HOVER  = S2;
constexpr ImU32 PREVIEW_BG  = S1;
constexpr ImU32 CHIP        = S2;
constexpr ImU32 CHIP_ON     = S3;
constexpr ImU32 TRACK       = BG_DEEP;   // трек слайдера утоплен под карточку
constexpr ImU32 POPOVER     = S2;        // всплывает над карточкой → на ступень выше
constexpr ImU32 MODAL       = S1;        // плавающая карточка над затемнением

constexpr ImU32 LINE        = HAIR;
constexpr ImU32 LINE2       = HAIR2;

constexpr ImU32 TEXT        = T1;
constexpr ImU32 TEXT_MUTED  = T2;
constexpr ImU32 TEXT_DIM    = T3;
constexpr ImU32 TEXT_FAINT  = T4;

// ── Акцент: единственный в интерфейсе ──────────────────────────────────────
constexpr ImU32 AMBER_TEXT  = rgb(0xE9C9A5);   // текст на янтарной подложке
constexpr ImU32 AMBER_FILL  = alpha(AMBER, TINT);
constexpr ImU32 AMBER_LINE  = alpha(AMBER, 0.38f);
constexpr ImU32 AMBER_NAV   = alpha(AMBER, 0.10f);
constexpr ImU32 AMBER_NAVLN = alpha(AMBER, 0.25f);
constexpr ImU32 SLIDER_LO   = AMBER_2;   // левый стоп заливки слайдера
constexpr ImU32 SLIDER_HI   = AMBER;

// Семантика отделена от акцента и появляется только заливкой пилюли или
// цветом дельты — поверхностью никогда (правило дизайн-системы).
constexpr ImU32 POS_BG      = alpha(POS, TINT);
constexpr ImU32 NEG_BG      = alpha(NEG, TINT);
constexpr ImU32 FOCUS_RING  = alpha(FOCUS, 0.20f);

constexpr ImU32 HP          = POS;   // HP всегда позитив, не настраивается
constexpr ImU32 SCRIM       = IM_COL32(0, 0, 0, 150);
constexpr ImU32 SWATCH_OFF  = S3;                     // кружок цвета у выключенной строки
constexpr ImU32 MODAL_SCRIM = alpha(BG_DEEP, 0.62f);  // TZ-Modal §1
constexpr ImU32 SKEL_NODE   = rgb(0x0B0F0E, 0.85f);   // узел скелета в ESP-превью (игровой слой)
constexpr ImU32 LOGO_TILE   = T1;                     // плитка под логотип
constexpr ImU32 ON_LIGHT    = BG;                     // галка поверх светлого образца

// ── ESP: дефолты элементов (TZ-Visuals-Players §3.2) ───────────────────────
namespace esp {
constexpr ImU32 BOX       = rgb(0xC2B49A);  // песок
constexpr ImU32 SKELETON  = rgb(0x6FA08A);  // шалфей
constexpr ImU32 NAME      = rgb(0x7A9BB5);  // стальной голубой
constexpr ImU32 TEAM      = rgb(0xB06060);  // глина
constexpr ImU32 WEAPON    = rgb(0xC08A5A);  // терракота
constexpr ImU32 AMMO      = rgb(0x9AA28A);  // олива
constexpr ImU32 DISTANCE  = rgb(0x6B7DA6);  // индиго-серый
constexpr ImU32 CORPSE    = rgb(0x7A8288);  // слейт
}

// Боты подаются тише игроков. Все цвета — из полевой палитры ТЗ (FIELD ниже),
// чтобы бот и игрок различались на экране, но обои оставались в одной гамме.
namespace esp_bot {
constexpr ImU32 BOX       = rgb(0x9AA28A);  // олива
constexpr ImU32 SKELETON  = rgb(0x5E8A6E);  // тёмный шалфей
constexpr ImU32 NAME      = rgb(0x7A8288);  // слейт
constexpr ImU32 WEAPON    = rgb(0x977F6A);  // тусклая терракота
constexpr ImU32 AMMO      = rgb(0x7D8B5A);  // тёмная олива
constexpr ImU32 DISTANCE  = rgb(0x6E8FA6);  // приглушённый индиго
constexpr ImU32 CORPSE    = rgb(0x4E5A50);  // тёмный мох
}

// ── Тиры брони T1..T6 (TZ-Visuals-Players §3.3) ────────────────────────────
constexpr ImU32 ARMOR_TIER[6] = {
    rgb(0x7A8288),  // T1 слейт
    rgb(0x5E8A6E),  // T2 зелёный
    rgb(0x7A9BB5),  // T3 голубой
    rgb(0xC7A05C),  // T4 песочное золото
    rgb(0xB06060),  // T5 бордовый
    rgb(0x8E7FB0),  // T6 лаванда
};
// Тир приходит из игры как 1..6; здесь один вход, чтобы не городить клампы.
constexpr ImU32 armor_tier_col(int tier_1based) {
    return ARMOR_TIER[tier_1based < 1 ? 0 : (tier_1based > 6 ? 5 : tier_1based - 1)];
}

// ── Полевая палитра модалки цвета (TZ-Modal §6.4): 30 цветов по светлоте ───
constexpr unsigned FIELD[30] = {
    0xE8E6E1, 0xD9C8B4, 0xC2B49A, 0xC4B45E, 0xB5A3C4, 0xA8B0A0, 0x8FB0A4, 0xC7A05C, 0x9AA28A, 0xC08A5A,
    0x7A9BB5, 0x6FA08A, 0xA07E96, 0x8E7FB0, 0xB07A6E, 0x6E8FA6, 0x5E9494, 0x977F6A, 0x7D8B5A, 0x7A8288,
    0x6B7DA6, 0x5E8A6E, 0xA46A5A, 0xB06060, 0x8A5A5A, 0x5A6E5A, 0x4E5A50, 0x4A5568, 0x3A4038, 0x2E3236,
};

// ── Радар (TZ-Radar §8) ────────────────────────────────────────────────────
namespace radar {
constexpr ImU32 DISC      = rgb(0x060608, 0.52f);
constexpr ImU32 DISC_LINE = wht(0.14f);
constexpr ImU32 RING      = wht(0.07f);
constexpr ImU32 DOT_LINE  = rgb(0x060608, 0.85f);
constexpr ImU32 PMC       = esp::TEAM;                // #B06060
constexpr ImU32 BOT       = esp::AMMO;                // #9AA28A
constexpr ImU32 CORPSE    = esp::CORPSE;              // #7A8288
constexpr ImU32 LOOT      = ARMOR_TIER[3];            // #C7A05C
constexpr ImU32 SELF      = AMBER;
constexpr ImU32 CONE_PMC  = rgb(0xB06060, 0.42f);     // §5.3 альфа центра конуса
constexpr ImU32 CONE_BOT  = rgb(0x9AA28A, 0.40f);
// Превью радара в панели живёт на карточке, а не на игровом кадре, поэтому
// диск плотнее игрового, а подпись радиуса имеет свою подложку.
constexpr ImU32 PREVIEW_DISC = rgb(0x0A0C0B, 0.92f);
constexpr ImU32 CAPTION_BG   = rgb(0x08080A, 0.80f);
}

// ── Ценность лута (TZ-Top-Loot §6) ─────────────────────────────────────────
namespace loot {
constexpr ImU32 TIER[6] = {
    rgb(0xC7A05C),  // ≥ 1M      легендарный
    rgb(0xB06060),  // 500k–1M   эпический
    rgb(0xC08A5A),  // 300–500k  редкий
    rgb(0x8E7FB0),  // 150–300k  необычный
    rgb(0x7A9BB5),  // 70–150k   обычный
    rgb(0x6FA08A),  // < 70k     дешёвый
};
constexpr int tier_of(uint32_t price) {
    return price >= 1000000u ? 0
         : price >=  500000u ? 1
         : price >=  300000u ? 2
         : price >=  150000u ? 3
         : price >=   70000u ? 4
                             : 5;
}
constexpr ImU32 PANEL_BG  = rgb(0x0E0E12, 0.86f);
constexpr ImU32 PANEL_LINE = wht(0.08f);   // рамка HUD, не интерфейсный hair
constexpr ImU32 BAR_TRACK = wht(0.06f);
// Маркеры лута в мире (фильтры на странице «Лут»).
constexpr ImU32 MARK_COMMON = rgb(0xC2B49A);   // песок
constexpr ImU32 MARK_RARE   = rgb(0xC7A05C);   // песочное золото
constexpr ImU32 MARK_QUEST  = rgb(0xB5A3C4);   // лаванда
}

// ── Остаток магазина (TZ-Ammo-Counter §4) ──────────────────────────────────
namespace ammo {
constexpr ImU32 OK    = esp::AMMO;      // > 1/3   олива
constexpr ImU32 LOW   = esp::WEAPON;    // ≤ 1/3   терракота
constexpr ImU32 EMPTY = esp::TEAM;      // 0       бордовый
constexpr ImU32 TRACK = wht(0.10f);
constexpr ImU32 SUB   = TEXT_MUTED;
constexpr ImU32 SHADOW = blk(0.85f);
constexpr ImU32 state_col(int cur, int max) {
    return cur <= 0                       ? EMPTY
         : (max > 0 && cur * 3 <= max)    ? LOW
                                          : OK;
}
}

// ── Состояния целей (TZ-Overlay-HUD §4.3-4.4) ──────────────────────────────
// Эти же цвета перекрывают пользовательские свотчи в мировом ESP: «вижу сквозь
// укрытие» и «труп» — это состояние, а не настройка.
namespace state {
constexpr ImU32 VISIBLE = rgb(0x6FA08A);   // шалфей
constexpr ImU32 NORMAL  = TEXT_MUTED;
constexpr ImU32 HOSTILE = rgb(0xB06060);   // глина
constexpr ImU32 DEAD    = esp::CORPSE;     // слейт
}

// ── Чипы статуса и карточки целей (TZ-Overlay-HUD §2-4) ────────────────────
// ВАЖНО: рамки игрового HUD — .08, а не интерфейсный hair .07. Значения
// замерены в ТЗ поверх яркого игрового кадра, где .07 пропадает. Панель
// (собственный непрозрачный грунт) живёт по hair/hair2, HUD по своим ТЗ.
namespace hud {
constexpr ImU32 HUD_HAIR     = wht(0.08f);
constexpr ImU32 CHIP_BG      = rgb(0x0E0E12, 0.80f);
constexpr ImU32 CHIP_LINE    = HUD_HAIR;
constexpr ImU32 CHIP_LABEL   = TEXT_MUTED;
constexpr ImU32 CHIP_VALUE   = TEXT;
constexpr ImU32 CHIP_ACC_BG  = alpha(AMBER, 0.10f);
constexpr ImU32 CHIP_ACC_LN  = alpha(AMBER, 0.32f);
constexpr ImU32 CHIP_ACC_TX  = AMBER_TEXT;

constexpr ImU32 ROW_LIVE     = rgb(0x141418, 0.86f);
constexpr ImU32 ROW_DEAD     = rgb(0x101014, 0.60f);
constexpr ImU32 BORDER_DEF   = HUD_HAIR;
constexpr ImU32 BORDER_DEAD  = wht(0.05f);
constexpr ImU32 BORDER_VIS   = rgb8(0x6FA08A, 76);   // шалфей .30
constexpr ImU32 BORDER_PRI   = rgb8(0xB06060, 66);   // глина .26

constexpr ImU32 DOT_VIS      = state::VISIBLE;
constexpr ImU32 DOT_NORM     = state::NORMAL;
constexpr ImU32 DOT_PRI      = state::HOSTILE;
constexpr ImU32 DOT_DEAD     = TEXT_FAINT;

constexpr ImU32 MAG_FULL     = esp::AMMO;     // олива
constexpr ImU32 MAG_LOW      = esp::WEAPON;   // терракота
constexpr ImU32 ARMOR_BG     = wht(0.05f);

constexpr ImU32 VIS_BG       = rgb(0x6FA08A, 0.12f);
constexpr ImU32 VIS_LINE     = rgb8(0x6FA08A, 87);   // шалфей .34
constexpr ImU32 DEAD_BG      = wht(0.04f);
constexpr ImU32 DEAD_LINE    = wht(0.08f);
}

}  // namespace abi::pal
