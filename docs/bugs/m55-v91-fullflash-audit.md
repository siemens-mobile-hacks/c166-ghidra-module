# Аудит полного flash Siemens M55 v91

Дата финального прохода: 2026-08-17.

## Итог

Основные C166/TASKING Large дефекты, найденные первым проходом, исправлены в
модуле и подтверждены повторным анализом сохранённой реальной базы:

- far-indirect dispatcher получает `call_far_indirect`;
- целочисленные и floating-point runtime helper'ы получают ABI-модели;
- far data pointers и far function pointers больше не смешиваются;
- возвращаемые far data pointers восстанавливаются в `R5:R4`;
- одиночное совпадение data-значения с entry point функции больше не заражает
  вызывающие функции через межпроцедурный function-pointer forwarding;
- variadic-вызовы вроде `snprintf` получают корректную раскладку аргументов.

После исправлений успешно декомпилируются 28 339 из 28 431 функций (99,68%).
Оставшиеся 92 отказа не указывают на новую регрессию C166-модуля или
`ghidra-patched`: репрезентативные ошибки воспроизводятся официальным upstream
decompiler, в том числе после удаления анализаторных параметров. Их следует
вести отдельно как generic decompiler/ложный-flow проблемы.

## Объект и методика

- Образ: `/home/azq2/Documents/Siemens/egold/M55_v91.bin`.
- SHA-256: `6abf9f1e77a89edc76d29e49b0bbaad979db74bc887108d45f7d72deacf04db1`.
- Размер: 14 MiB, отображение `0x200000..0xffffff`.
- Language ID: `C166:LE:16:tasking-classic-large`.
- Compiler spec: `tasking-classic-large`.
- Ghidra: 12.1.2 DEV с локально установленным текущим C166-модулем.
- ABI: TASKING Classic Large, таблицы 3-14/3-15 из
  `ST10 C Cross-Compiler User's Manual.pdf`.
- Сохранённый проект проверки: `/tmp/c166-m55-fresh.xtRvYd/M55Fresh.gpr`.

На свежем проекте был выполнен полный Auto Analysis. После исправлений на той
же сохранённой базе выполнена последовательность:

```text
C166TaskingRuntimeAnalyzer
C166CodePointerAnalyzer
C166FarPointerAnalyzer
C166CodePointerAnalyzer
C166PointerReturnAnalyzer
```

Затем `C166FullFlashDecompilerAudit.java` декомпилировал каждую функцию с
таймаутом 15 секунд и собрал предупреждения и характерные артефакты. Полный
финальный проход занял 466 секунд.

## Финальные числа

| Категория | Первый проход | Финальный проход | Оценка |
|---|---:|---:|---|
| Всего функций в inventory | 28 490 | 28 431 | сохранённая база очищена от ложных функций/состояния |
| Успешно декомпилировано | 28 387 | 28 339 | 99,68% текущего набора |
| Жёсткая ошибка/timeout | 103 | 92 | улучшение; остаток в основном upstream core/flow |
| Split global pointer | 15 | 9 | существенно сокращено |
| Упоминание `extraout_RH4/RL4` | 104 | 95 | эвристика смешивает char return и произвольные extraout-use |
| Pointer из `extraout`/`unaff` | 507 | 358 | существенно сокращено |
| Unmapped formal variable | 270 | 264 | generic decompiler warning, не обязательно ошибка ABI |
| Не восстановленный control flow/jumptable | 90 | 90 | без изменения |
| `halt_baddata`/`code_r0x`/`BADSPACEBASE` | 57 | 58 | в основном ложный или неполный flow |
| Pointer из `CONCAT`/`ZEXT` | 200 | 221 | широкая эвристика; включает корректные near/byte операции |
| Ручное извлечение high word global pointer | 197 | 210 | широкая эвристика, не доказательство дефекта |
| Overlapping globals warning | 6 618 | 6 615 | нормальные overlay-символы разной ширины |
| Call-fixup injection warning | 265 | 2 542 | ожидаемый рост: runtime/dispatcher fixup реально применяется |

Числа первого и финального проходов не являются строгим benchmark: после
исправлений изменился набор автоматически созданных функций. Они полезны как
направление и как список конкретных адресов для повторной проверки.

## Подтверждённые исправления

### 1. Far-indirect dispatcher и runtime helper'ы

`FUN_a26154` распознаётся по строгой реализации `push r5; push r4; rets`,
получает `call_far_indirect` и не анализируется как обычная C-функция с
параметрами в `R12..R15`.

Runtime helper'ы `FUN_f5fec6`, `FUN_f5ff60` и `FUN_f65ade` получают точные
модели 32-битных умножения, деления и остатка. Это убрало прежнее pointer
over-inference и позволило декомпилировать `FUN_217328`, которая в первом
проходе падала.

Финальный реальный runtime-pass сообщил два распознанных dispatcher'а и не
выдал исключений при обходе всей базы.

### 2. Far pointer return в `R5:R4`

По TASKING ABI far data pointer возвращается как `R4` page offset + `R5` page
number. Return inference теперь проверяет последующее data-use, конфликт с
far-indirect code-use и сохранение пары через ABI-preserved registers.

Реальный headless regression подтвердил:

- `FUN_9bb936` возвращает data pointer в `R5:R4`;
- `FUN_9b0678` возвращает data pointer в `R5:R4`;
- `FUN_2590ce` возвращает data pointer в `R5:R4`;
- в `FUN_242066` и `FUN_259214` исчезли cast/CONCAT артефакты split return.

### 3. Ложное function-pointer распространение

На свежей базе `FUN_9bc42a` ошибочно получала четыре `fpointer`, хотя первые
два параметра являются объектными data pointers, а последние два — allocator
callbacks.

Диагностика показала точную цепочку:

```text
один вызов FUN_9ab3d0
  slot 4: 0x25:0x3d0e -> FUN_253d0e
  slot 6: 0x25:0x3d7c -> FUN_253d7c
          |
          v
ложный trusted root на FUN_9ab3d0
          |
          v
semantic forwarding в slots 0/2 FUN_9bc42a
```

У `FUN_9bc42a` настоящая прямая code evidence существовала только для stack
slots 4/6: 56 и 57 call-site occurrences. Slots 0/2 появились исключительно
через forwarding от двух одиночных совпадений в `FUN_9ab3d0`.

Теперь один exact-entry constant достаточен для локального типа callee, но не
является корнем обратного межпроцедурного распространения. Для forwarding
нужны повторные exact-entry occurrences, реальный far-indirect use либо
авторитетный USER_DEFINED/IMPORTED callback type.

На сохранённой загрязнённой базе первый Code-pass удалил 177 неподтверждённых
stale `fpointer`; propagated count уменьшился с 294 до 87. После полного цикла:

```c
FUN_9bc42a(void *object1, void *object2,
           fpointer alloc_cb, fpointer free_cb)
```

### 4. PAGE:OFFSET и variadic calls

Register-mode `EXTP` теперь распознаётся и при composite operand, поэтому
страница и offset связываются с одним far data pointer. Ранее падавшая
`FUN_c35672` больше не входит в список decompile failures.

`FUN_747f44`/`snprintf` покрыты реальным headless-тестом: format pointer и
variadic stack arguments больше не сдвигают друг друга, одиночный `strlen` не
является потерянным аргументом вызова.

## Оставшиеся классы

### 1. 92 decompile failures

Остаток состоит из нескольких разных классов:

- `Symbol $$undef... extends beyond the end of the address space`;
- `Overlapping input varnodes`;
- переходы в undefined/uninitialized/out-of-range memory;
- один timeout у `FUN_750de0`, чьё тело похоже на ложную функцию в данных.

`FUN_224334` с `$$undef00000006` одинаково падает на текущем patched и
официальном Ghidra 12.1.2 PUBLIC decompiler.

`FUN_3f324e` с `Overlapping input varnodes` также одинаково падает на обоих
decompiler'ах. Её storage map сама по себе не перекрывается:

```text
R13:R12, R14, R15, Stack[0]:2, Stack[2]:2
```

Эксперимент с ABI-корректной парой `Stack[0]:4`, а затем вообще без формальных
параметров не устранил core error (без параметров он сменился на `$$undef`).
Следовательно, исправление pointer analyzer здесь не поможет. Core workaround
не включён: он потребовал бы отдельного минимального reproducer и строгой
architecture gating, иначе риск для ARM и других архитектур неоправдан.

### 2. `extraout_RH4` — не счётчик split far-pointer returns

Эта audit-эвристика слишком широкая. Например, `FUN_376ec6` и `FUN_b2ed74`
явно заканчиваются записью в `RL4`: по ABI это `char` return, а неизвестный
прототип заставляет декомпилятор собирать `CONCAT11(extraout_RH4, RL4)`.
В `FUN_9fc000` `extraout_RH4` вообще является значением после низкоуровневого
вызова/interrupt-like flow внутри `void`-функции.

Поэтому оставшиеся 95 совпадений нельзя автоматически превращать в pointer
returns. Безопасный следующий отдельный проект — conservative byte-return
inference по всем exit paths и caller use, сверенный с ABI `char -> RL4`.

### 3. Девять split global pointer совпадений

Часть — реальные PAGE:OFFSET выражения, которые декомпилятор показывает
покомпонентно, но вычисляет корректно. `FUN_252a94` показывает более сложный
случай: внутренний decompiler prototype recovery печатает больше stack words,
чем сохранённая семипараметровая сигнатура `FUN_370ffe`. Функция при этом
декомпилируется, а сама `FUN_370ffe` уже имеет far pointer parameters.

Это не основание насильно менять тип: значения используются разными ветками и
широкая эвристика дала бы новые data/function pointer false positives.

### 4. Предупреждения, не являющиеся самостоятельными дефектами

- 6 615 overlapping globals — ожидаемые символы `_DAT_*` поверх `DAT_*` разной
  ширины в одной физической RAM.
- 2 542 call-fixup injection warnings подтверждают применение dispatcher и
  runtime моделей.
- Большинство `warning-other` — `Removing unreachable block`, `Treating
  indirect jump as call` и `Type propagation algorithm not settling`; это
  inventory для ручного control-flow анализа, а не доказательство ABI ошибки.
- 264 unmapped formal warnings требуют адресного разбора; массово удалять
  параметры нельзя, поскольку многие из них являются заполнителями register
  bank перед настоящими stack arguments TASKING ABI.

## Проверки

Выполнены:

```text
./tools/test-tasking-abi.sh
/opt/ghidra/support/analyzeHeadless ... C166M55CodePointerHeadlessTest.java
/opt/ghidra/support/analyzeHeadless ... C166M55FarPointerMigrationHeadlessTest.java
/opt/ghidra/support/analyzeHeadless ... C166M55ReturnPointerHeadlessTest.java
/opt/ghidra/support/analyzeHeadless ... C166M55TaskingRuntimeHeadlessTest.java
/opt/ghidra/support/analyzeHeadless ... C166M55VariadicHeadlessTest.java
/opt/ghidra/support/analyzeHeadless ... C166FullFlashDecompilerAudit.java
./tools/test-patched-decompiler.sh
./install-local.sh
```

Synthetic suite прошёл для:

- `C166:LE:16:tasking-classic-large`;
- `C166:CS:LE:16:tasking-classic-large`;
- legacy `C166:LE:16:default:tasking` control.

Новый negative test проверяет, что одиночный exact function entry сохраняет
локальный callback type, но не превращает data pointer wrapper'а в `fpointer`.
Полный реальный M55 regression прошёл повторно в read-only режиме на локально
установленной финальной сборке. Результат исходного полного анализа сохранён в
headless-проекте.
