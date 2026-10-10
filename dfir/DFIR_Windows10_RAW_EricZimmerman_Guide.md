# Пошаговое руководство DFIR: Windows 10 RAW-образ с Eric Zimmerman Tools

**Цель:** поиск следов APT и компрометации Windows 10  
**Среда анализа:** Windows с PowerShell  
**Формат источника:** RAW/DD  
**Статус:** базовая воспроизводимая методика; команды и параметры необходимо сверять со справкой установленной версии инструментов.

> **Важное замечание.** Проводите исследование только на основании законного разрешения. Не загружайте исследуемую ОС и не запускайте подозрительные файлы. Сохраняйте оригинал неизменным. Отсутствие артефакта не доказывает отсутствие активности, а отдельная запись обычно не доказывает компрометацию.

## 1. План расследования

1. Зафиксировать источник и целостность образа.
2. Подключить RAW-образ в режиме только для чтения.
3. Определить раздел Windows и зафиксировать параметры системы.
4. Извлечь нужные артефакты, сохранив оригиналы и сопутствующие файлы.
5. Обработать журналы событий, реестр, Prefetch, Amcache, NTFS и пользовательские артефакты.
6. Проверить подозрительные события и возможные механизмы закрепления.
7. Нормализовать время и построить временную шкалу.
8. Сформировать IOC, выводы и отчёт с указанием ограничений.

## 2. Подготовка рабочей структуры

Пример ниже использует исходный образ `E:\Evidence\windows10.raw`, каталог инструментов `D:\DFIR\Tools` и дело `D:\DFIR\CASE-001`. Замените пути на фактические.

Откройте PowerShell от имени администратора:

```powershell
$Case   = "D:\DFIR\CASE-001"
$Image  = "E:\Evidence\windows10.raw"
$Tools  = "D:\DFIR\Tools"
$Output = "$Case\Output"
$Logs   = "$Case\Logs"
$Extract = "$Case\Extracted"

$dirs = @(
    "$Case\Evidence", "$Case\Hashes", "$Case\Notes",
    $Output, $Logs, $Extract,
    "$Output\EventLogs", "$Output\Registry",
    "$Output\Execution", "$Output\FileSystem",
    "$Output\UserActivity", "$Output\Network",
    "$Output\Timeline", "$Output\IOC",
    "$Extract\NTFS"
)
New-Item -ItemType Directory -Path $dirs -Force | Out-Null

if (-not (Test-Path -LiteralPath $Image -PathType Leaf)) {
    throw "RAW-образ не найден: $Image"
}
if (-not (Test-Path -LiteralPath $Tools -PathType Container)) {
    throw "Каталог инструментов не найден: $Tools"
}

@"
Case ID: CASE-001
Image: $Image
Analysis workstation: $env:COMPUTERNAME
Analyst account: $env:USERDOMAIN\$env:USERNAME
Start time UTC: $([DateTime]::UtcNow.ToString("o"))
"@ | Set-Content "$Case\Notes\case-notes.txt" -Encoding UTF8
```

## 3. Зафиксировать SHA-256 исходного образа

```powershell
Get-Item -LiteralPath $Image |
    Select-Object FullName, Length, CreationTimeUtc, LastWriteTimeUtc |
    Export-Csv "$Case\Hashes\image-metadata.csv" -NoTypeInformation -Encoding UTF8

Get-FileHash -LiteralPath $Image -Algorithm SHA256 |
    Format-List |
    Out-File "$Case\Hashes\image-sha256.txt" -Encoding UTF8
```

Сохраните результат в журнале дела. Если образ состоит из нескольких частей, вычислите хеш каждой части. Хешируйте повторно в конце исследования и сравните результаты.

## 4. Подключить RAW-образ только для чтения

Можно использовать Arsenal Image Mounter: https://arsenalrecon.com/products/arsenal-image-mounter/downloads

1. Запустите инструмент с административными правами.
2. Выберите RAW/DD-образ и подключите его как диск.
3. Выберите режим **Read-only**.
4. Не соглашайтесь на инициализацию, форматирование или исправление файловой системы.
5. Запишите обнаруженные разделы и букву тома Windows.

Далее для примера предполагается, что Windows доступна как `R:`:

```powershell
$Win = "R:\"

Test-Path "R:\Windows\System32\config\SYSTEM"
Test-Path "R:\Windows\System32\winevt\Logs"
Test-Path "R:\Windows\Prefetch"

Get-Disk |
    Format-Table Number, FriendlyName, OperationalStatus,
                 IsReadOnly, IsOffline, PartitionStyle -AutoSize

Get-Partition |
    Format-Table DiskNumber, PartitionNumber, DriveLetter, Type, Size -AutoSize
```

Не полагайтесь только на `IsReadOnly`: подтвердите режим в программе монтирования и не выполняйте операции записи. Если RAW содержит образ отдельного раздела, а не всего диска, процедура определения тома будет отличаться.

## 5. Установить Eric Zimmerman Tools

Официальный каталог: https://ericzimmerman.github.io/  
Документация KAPE: https://ericzimmerman.github.io/KapeDocs/

Загрузите инструменты и скрипт установки только из официального источника. После сохранения `Get-ZimmermanTools.ps1`, например в `D:\DFIR\Get-ZimmermanTools.ps1`, проверьте его параметры:

```powershell
Get-Help "D:\DFIR\Get-ZimmermanTools.ps1" -Full
```

Пример запуска для версии .NET 9 (проверьте актуальность параметров в справке):

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
& "D:\DFIR\Get-ZimmermanTools.ps1" -Dest "$Tools" -NetVersion 9
```

Найдите ключевые исполняемые файлы:

```powershell
Get-ChildItem $Tools -Recurse -File -Include `
    EvtxECmd.exe,RECmd.exe,PECmd.exe,AmcacheParser.exe,`
    AppCompatCacheParser.exe,MFTECmd.exe,LECmd.exe,JLECmd.exe,`
    SBECmd.exe,RBCmd.exe,SrumECmd.exe,TimelineExplorer.exe |
    Select-Object Name, FullName
```

Путь к EXE в последующих командах нужно поправить, если он расположен во вложенном каталоге. Параметры могут меняться между версиями; при сомнениях запускайте `инструмент --help` и сверяйтесь с README.

## 6. Извлечь артефакты в рабочий каталог

Для первичной обработки скопируйте системные журналы, кусты реестра и базы приложений с подключённого тома. Сохраните исходный том неизменным. Копирование файлов не заменяет извлечение структур NTFS и не сохраняет весь контекст диска.

```powershell
$paths = @(
    "Windows\System32\winevt\Logs",
    "Windows\System32\config",
    "Windows\Prefetch",
    "Windows\AppCompat\Programs",
    "Windows\System32\sru",
    "Windows\System32\Tasks"
)

foreach ($relative in $paths) {
    $source = Join-Path $Win $relative
    $dest = Join-Path $Extract $relative

    if (Test-Path -LiteralPath $source) {
        New-Item -ItemType Directory -Path $dest -Force | Out-Null
        robocopy $source $dest /E /COPY:DAT /DCOPY:DAT /R:0 /W:0 /XJ `
            /LOG+:"$Logs\robocopy.log"

        if ($LASTEXITCODE -ge 8) {
            "ERROR copying $source; robocopy exit code $LASTEXITCODE" |
                Out-File "$Logs\copy-errors.txt" -Append -Encoding UTF8
        }
    }
}
```

Скопируйте пользовательские артефакты для каждого профиля отдельно, например:

- `Users\<user>\NTUSER.DAT` и соседние файлы `LOG1`/`LOG2`;
- `Users\<user>\AppData\Local\Microsoft\Windows\USRCLASS.DAT` и журналы;
- `Users\<user>\AppData\Roaming\Microsoft\Windows\Recent`;
- `Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations`;
- `Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations`;
- браузерные базы и другие артефакты, относящиеся к гипотезе.

Хешируйте собранные файлы:

```powershell
Get-ChildItem $Extract -Recurse -File |
    ForEach-Object { Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 } |
    Export-Csv "$Case\Hashes\extracted-files-sha256.csv" -NoTypeInformation -Encoding UTF8
```

Учитывайте, что копирование обычных файлов не извлекает `$MFT`, `$UsnJrnl:$J`, `$LogFile` и нераспределённое пространство. Для них используйте форензический инструмент, умеющий читать метаданные тома, либо KAPE с подходящим Target.

## 7. Обработать журналы событий — EvtxECmd

Официальный репозиторий: https://github.com/EricZimmerman/evtx

```powershell
$Evtx = "$Tools\EvtxECmd.exe"
$EvtxIn = "$Extract\Windows\System32\winevt\Logs"
$EvtxOut = "$Output\EventLogs"
New-Item -ItemType Directory -Path $EvtxOut -Force | Out-Null

& $Evtx -d $EvtxIn --csv $EvtxOut 2>&1 |
    Tee-Object "$Logs\EvtxECmd-console.txt"
"Exit code: $LASTEXITCODE" |
    Out-File "$Logs\EvtxECmd-exit.txt" -Encoding UTF8
```

Проверьте созданные CSV:

```powershell
Get-ChildItem $EvtxOut -File |
    Select-Object Name, Length, LastWriteTime
```

### Приоритетные события

| Журнал | Event ID | Значение для расследования |
|---|---:|---|
| Security | 4624, 4625 | Успешные и неуспешные входы |
| Security | 4648 | Использование явных учётных данных |
| Security | 4672 | Назначение специальных привилегий |
| Security | 4688 | Создание процесса, если аудит включён |
| Security | 4697 | Установка службы, если событие зарегистрировано |
| Security | 4698–4702 | Создание и изменение заданий планировщика |
| Security | 4719 | Изменение политики аудита |
| Security | 1102 | Очистка журнала Security |
| System | 7045 | Установка службы |
| PowerShell Operational | 4103, 4104 | Журналирование модулей и блоков сценариев |
| Defender Operational | 1116, 1117 | Обнаружение угрозы и действия защиты |

Проверьте канал журнала, XML-поля, пользователя, время, процесс и соседние события. Идентификаторы — лишь отправная точка: события могут отсутствовать, если аудит не был включён или журналы очищены/перезаписаны.

Первичный поиск строк в CSV:

```powershell
$patterns = @(
    "powershell", "rundll32", "regsvr32", "mshta",
    "wscript", "cscript", "schtasks", "psexec",
    "encodedcommand", "frombase64string"
)

Get-ChildItem $EvtxOut -Filter "*.csv" |
    ForEach-Object {
        Select-String -Path $_.FullName -Pattern $patterns `
            -SimpleMatch -CaseSensitive:$false
    } |
    Out-File "$Output\EventLogs\suspicious-strings.txt" -Encoding UTF8
```

Это только первичный фильтр: он может пропустить команды в структурированных полях и давать ложные срабатывания.

## 8. Проанализировать реестр — Registry Explorer и RECmd

Откройте копии кустов в Registry Explorer:

```text
Extracted\Windows\System32\config\SYSTEM
Extracted\Windows\System32\config\SOFTWARE
Extracted\Windows\System32\config\SAM
Extracted\Windows\System32\config\SECURITY
```

Также исследуйте пользовательские `NTUSER.DAT` и `USRCLASS.DAT` каждого профиля. Сохраняйте рядом доступные `LOG1`/`LOG2`. Не восстанавливайте кусты поверх оригинальных доказательств.

### Основные направления

| Объект | Что проверять |
|---|---|
| Run/RunOnce | Автозагрузка в HKLM/HKCU |
| `SYSTEM\CurrentControlSet\Services` | Службы и их пути |
| `SYSTEM\...\Enum\USB`, `USBSTOR` | Подключённые USB-устройства |
| UserAssist | Следы пользовательской активности |
| RecentDocs | Недавние документы |
| ShellBags | Следы просмотра каталогов |
| Image File Execution Options | Необычные параметры отладки/перехвата |
| AppInit DLL | Подозрительные библиотеки и параметры загрузки |

Учитывайте WOW6432Node, пользовательские SID и соответствующий ControlSet в кусте SYSTEM.

### RECmd

```powershell
$RECmd = "$Tools\RECmd.exe"
& $RECmd --help

Get-ChildItem $Tools -Recurse -File -Filter "*.reb" |
    Select-Object FullName
```

Выберите подходящий batch-файл, поставляемый с вашей версией инструментов:

```powershell
$Batch = "D:\DFIR\Tools\BatchExamples\RECmd.reb"
$Hive = "$Extract\Windows\System32\config\SYSTEM"
$RegOut = "$Output\Registry"

New-Item -ItemType Directory -Path $RegOut -Force | Out-Null

if ((Test-Path $Batch) -and (Test-Path $Hive)) {
    & $RECmd -f $Hive --bn $Batch --csv $RegOut 2>&1 |
        Tee-Object "$Logs\RECmd-SYSTEM.txt"
}
```

`RECmd.reb` — пример имени, а не гарантированное имя файла. Подставьте реально существующий batch-файл и проверьте его назначение и синтаксис в официальной документации: https://github.com/EricZimmerman/RECmd

Наличие ключа автозагрузки или службы само по себе не доказывает вредоносность. Проверяйте целевой файл, его хеш, время, подпись и подтверждения выполнения.

## 9. Исследовать запуск программ

### 9.1. PECmd — Prefetch

```powershell
$PECmd = "$Tools\PECmd.exe"
$PrefetchIn = "$Extract\Windows\Prefetch"
$PrefetchOut = "$Output\Execution\Prefetch"

New-Item -ItemType Directory -Path $PrefetchOut -Force | Out-Null
& $PECmd -d $PrefetchIn --csv $PrefetchOut 2>&1 |
    Tee-Object "$Logs\PECmd.txt"
```

Ищите неизвестные EXE, необычные пути, запуск скриптовых движков и средств удалённого администрирования, повторные запуски в подозрительный период. Prefetch может подтверждать запуск, но отсутствие файла `.pf` не доказывает, что программа не выполнялась.

### 9.2. AmcacheParser

```powershell
$AmcacheHive = "$Extract\Windows\AppCompat\Programs\Amcache.hve"
$AmcacheOut = "$Output\Execution\Amcache"
New-Item -ItemType Directory -Path $AmcacheOut -Force | Out-Null

if (Test-Path $AmcacheHive) {
    & "$Tools\AmcacheParser.exe" -f $AmcacheHive --csv $AmcacheOut 2>&1 |
        Tee-Object "$Logs\AmcacheParser.txt"
}
else {
    "Amcache.hve not found: $AmcacheHive" |
        Out-File "$Logs\missing-artifacts.txt" -Append -Encoding UTF8
}
```

Amcache содержит сведения о приложениях и файлах, но не является универсальным журналом выполнения. При необходимости проверьте в справке параметр `-i`.

### 9.3. AppCompatCacheParser — ShimCache

```powershell
$SystemHive = "$Extract\Windows\System32\config\SYSTEM"
$ShimOut = "$Output\Execution\ShimCache"
New-Item -ItemType Directory -Path $ShimOut -Force | Out-Null

if (Test-Path $SystemHive) {
    & "$Tools\AppCompatCacheParser.exe" -f $SystemHive --csv $ShimOut 2>&1 |
        Tee-Object "$Logs\AppCompatCacheParser.txt"
}
```

Используйте ShimCache как дополнительный источник сведений о путях файлов. Не интерпретируйте его запись как самостоятельное доказательство запуска.

## 10. Исследовать NTFS с MFTECmd

Официальный репозиторий: https://github.com/EricZimmerman/MFTECmd

### 10.1. Получить `$MFT`

`$MFT` — системная метаструктура NTFS; обычное копирование через `Copy-Item R:\$MFT` не является надёжным способом её извлечения. Используйте инструмент извлечения NTFS-артефактов, например подходящий Target KAPE или другой форензический инструмент, поддерживающий том.

Сохраните извлечённый файл как:

```text
D:\DFIR\CASE-001\Extracted\NTFS\$MFT
```

Проверьте размер и хеш:

```powershell
Get-Item "$Extract\NTFS\$MFT" |
    Select-Object FullName, Length, LastWriteTimeUtc
Get-FileHash "$Extract\NTFS\$MFT" -Algorithm SHA256
```

### 10.2. Обработать `$MFT`

```powershell
$MFTFile = "$Extract\NTFS\$MFT"
$MFTOut = "$Output\FileSystem\MFT"
New-Item -ItemType Directory -Path $MFTOut -Force | Out-Null

& "$Tools\MFTECmd.exe" -f $MFTFile --csv $MFTOut 2>&1 |
    Tee-Object "$Logs\MFTECmd-MFT.txt"
```

### 10.3. Обработать USN Journal

Извлеките поток `$UsnJrnl:$J` поддерживающим NTFS-инструментом и сохраните как обычный файл, например `Extracted\NTFS\UsnJrnl-J.bin`. Затем:

```powershell
$USNFile = "$Extract\NTFS\UsnJrnl-J.bin"
$USNOut = "$Output\FileSystem\USN"
New-Item -ItemType Directory -Path $USNOut -Force | Out-Null

if (Test-Path $USNFile) {
    & "$Tools\MFTECmd.exe" -f $USNFile --csv $USNOut 2>&1 |
        Tee-Object "$Logs\MFTECmd-USN.txt"
}
```

Проверьте формат и параметры текущей версии MFTECmd; используйте имя фактически извлечённого потока.

Ищите новые/переименованные/удалённые EXE, DLL, скрипты, архивы и документы; изменения в `AppData`, `ProgramData`, `Temp`, `Windows\System32`, каталогах автозагрузки и заданиях. Сопоставляйте `$STANDARD_INFORMATION`, `$FILE_NAME`, USN и другие источники. Различие временных меток не доказывает timestomping: возможны копирование, распаковка и другие легитимные причины.

## 11. Исследовать пользовательскую активность

Пути ниже приведены для примера. Убедитесь, что артефакты скопированы в рабочий каталог, если политика лаборатории требует не обращаться к смонтированному тому напрямую.

### LECmd — LNK

```powershell
$LnkOut = "$Output\UserActivity\LNK"
New-Item -ItemType Directory -Path $LnkOut -Force | Out-Null
& "$Tools\LECmd.exe" -d "R:\Users" --csv $LnkOut 2>&1 |
    Tee-Object "$Logs\LECmd.txt"
```

### JLECmd — Jump Lists

```powershell
$JumpOut = "$Output\UserActivity\JumpLists"
New-Item -ItemType Directory -Path $JumpOut -Force | Out-Null
& "$Tools\JLECmd.exe" -d "R:\Users" --csv $JumpOut 2>&1 |
    Tee-Object "$Logs\JLECmd.txt"
```

### SBECmd — ShellBags

```powershell
$ShellOut = "$Output\UserActivity\ShellBags"
New-Item -ItemType Directory -Path $ShellOut -Force | Out-Null
& "$Tools\SBECmd.exe" -d "R:\Users" --csv $ShellOut 2>&1 |
    Tee-Object "$Logs\SBECmd.txt"
```

### RBCmd — Корзина

```powershell
$RecycleIn = 'R:\$Recycle.Bin'
$RecycleOut = "$Output\UserActivity\RecycleBin"
New-Item -ItemType Directory -Path $RecycleOut -Force | Out-Null

if (Test-Path $RecycleIn) {
    & "$Tools\RBCmd.exe" -d $RecycleIn --csv $RecycleOut 2>&1 |
        Tee-Object "$Logs\RBCmd.txt"
}
```

### SrumECmd — SRUM

```powershell
$SRUM = "$Extract\Windows\System32\sru\SRUDB.dat"
$SoftwareHive = "$Extract\Windows\System32\config\SOFTWARE"
$SRUMOut = "$Output\Network\SRUM"
New-Item -ItemType Directory -Path $SRUMOut -Force | Out-Null

if ((Test-Path $SRUM) -and (Test-Path $SoftwareHive)) {
    & "$Tools\SrumECmd.exe" -f $SRUM -r $SoftwareHive --csv $SRUMOut 2>&1 |
        Tee-Object "$Logs\SrumECmd.txt"
}
```

Проверьте параметры по справке установленной версии. SRUM не является полным сетевым журналом и не гарантирует наличие URL, содержимого трафика или всех удалённых адресов.

### USB и внешние носители

В Registry Explorer проверьте:

- `SYSTEM\CurrentControlSet\Enum\USBSTOR`;
- `SYSTEM\CurrentControlSet\Enum\USB`;
- `SYSTEM\MountedDevices`;
- доступные события подключения устройств.

Сопоставьте идентификаторы и серийные номера устройств с LNK, Jump Lists, ShellBags и файловой хронологией. Наличие записи об устройстве не доказывает копирование конкретного файла.

## 12. Проверить возможные TTP и механизмы закрепления

Используйте найденные артефакты для проверки гипотез по MITRE ATT&CK. Не приписывайте активность конкретной APT-группе только на основании одной техники.

| Направление | Что искать | Источники |
|---|---|---|
| Первоначальный доступ | Подозрительные документы, архивы, загруженные файлы | LNK, Jump Lists, MFT, браузерные артефакты, EVTX |
| Выполнение | PowerShell, WMI, скриптовые движки, неизвестные EXE | EVTX, Prefetch, Amcache, MFT |
| Закрепление | Run-ключи, службы, задачи, WMI-подписки | Реестр, Tasks, EVTX |
| Повышение привилегий | Подозрительные входы и процессы | Security EVTX, службы и процессы |
| Сокрытие следов | Очистка журналов, удаление файлов, изменения метаданных | EVTX, USN, MFT, Defender |
| Сбор данных | Архивы, копирование документов, временные каталоги | MFT, LNK, Jump Lists, ShellBags |
| Возможная эксфильтрация | Подготовка архивов, доступные сетевые индикаторы | SRUM, журналы приложений и сети |

Для каждого объекта фиксируйте путь/ключ, значение, время, пользователя, хеш целевого файла, связанные события, подтверждения выполнения и альтернативные объяснения.

## 13. Сформировать временную шкалу

Используйте Timeline Explorer для просмотра CSV. Не объединяйте CSV разных инструментов без нормализации: имена и семантика временных полей различаются.

Рекомендуемые поля итоговой таблицы:

- `TimestampUTC` — нормализованное время UTC;
- `TimestampOriginal` — исходное значение;
- `Source` — источник: EVTX, MFT, Prefetch и т. д.;
- `User` — пользователь;
- `Process` — процесс/файл;
- `Path` — путь или объект;
- `Event` — описание;
- `EvidenceFile` — исходный артефакт;
- `Confidence` — уверенность;
- `Notes` — комментарии.

Найдите созданные CSV:

```powershell
Get-ChildItem $Output -Recurse -File -Filter "*.csv" |
    Select-Object FullName, Length
```

Пример фильтрации после того, как вы подготовили объединённую таблицу `$Timeline` с нормализованным полем `TimestampUTC`:

```powershell
$Start = [DateTimeOffset]::Parse("2026-09-01T00:00:00Z")
$End   = [DateTimeOffset]::Parse("2026-09-03T00:00:00Z")

$Timeline |
    Where-Object {
        $t = [DateTimeOffset]::Parse($_.TimestampUTC)
        $t -ge $Start -and $t -lt $End
    } |
    Sort-Object TimestampUTC |
    Export-Csv "$Output\Timeline\incident-window.csv" -NoTypeInformation -Encoding UTF8
```

Даты условны. Этот фрагмент предполагает, что `$Timeline` уже создан и все значения приведены к UTC. Он не объединяет CSV автоматически.

Коррелируйте цепочки: появление файла → запуск → изменение реестра/создание службы → последующая активность. Совпадение времени само по себе не доказывает причинно-следственную связь.

## 14. Создать перечень IOC

Создайте каталог:

```powershell
New-Item -ItemType Directory -Path "$Output\IOC" -Force | Out-Null
```

Пример расчёта хешей известных подозрительных файлов:

```powershell
$SuspectPaths = @(
    "R:\Users\user\AppData\Roaming\suspicious.exe",
    "R:\ProgramData\unknown\service.dll"
)

$IOC = foreach ($path in $SuspectPaths) {
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        $file = Get-Item -LiteralPath $path
        $hash = Get-FileHash -LiteralPath $path -Algorithm SHA256

        [PSCustomObject]@{
            Path             = $file.FullName
            Size             = $file.Length
            CreationTimeUTC  = $file.CreationTimeUtc.ToString("o")
            LastWriteTimeUTC = $file.LastWriteTimeUtc.ToString("o")
            SHA256           = $hash.Hash
        }
    }
}

$IOC |
    Export-Csv "$Output\IOC\file-ioc.csv" -NoTypeInformation -Encoding UTF8
```

Замените примеры путей на реальные. Время из `Get-Item` может не отражать полную историю NTFS, поэтому сверяйте его с `$MFT`, USN и другими источниками.

Для каждого IOC укажите тип, значение, источник, время, контекст, уровень уверенности и основание классификации. Не помечайте IP или домен как вредоносный без подтверждающих данных.

## 15. Контроль качества

```powershell
Get-ChildItem $Logs -File |
    Select-Object Name, Length, LastWriteTime

Get-ChildItem $Output -Recurse -File |
    Group-Object Extension |
    Sort-Object Count -Descending |
    Select-Object Name, Count

Get-FileHash -LiteralPath $Image -Algorithm SHA256 |
    Format-List |
    Out-File "$Case\Hashes\image-sha256-final.txt" -Encoding UTF8
```

Сравните исходный и конечный SHA-256 образа. Проверьте логи парсеров, ошибки копирования, пропущенные артефакты, версии инструментов и использованные batch-файлы. Зафиксируйте ограничения: отсутствие журналов, перезапись данных, неполное извлечение NTFS, недоступные пользовательские профили и другие проблемы.

## 16. Чек-лист расследования

- [ ] Исходный образ идентифицирован и захеширован.
- [ ] Образ подключён только для чтения.
- [ ] Зафиксированы версии инструментов и параметры запуска.
- [ ] Сохранены EVTX и системные/пользовательские кусты реестра.
- [ ] Обработаны Prefetch, Amcache и ShimCache.
- [ ] Извлечены и обработаны `$MFT` и доступный USN Journal.
- [ ] Исследованы LNK, Jump Lists, ShellBags и Корзина.
- [ ] Проверены USB-артефакты и механизмы закрепления.
- [ ] Построена временная шкала UTC.
- [ ] Ключевые выводы подтверждены несколькими источниками.
- [ ] IOC имеют источник и контекст.
- [ ] Сохранены логи обработки и хеши.
- [ ] Итоговый отчёт содержит ограничения и альтернативные объяснения.

## 17. Шаблон итогового отчёта

# Отчёт по результатам форензического исследования образа Windows 10

**Номер дела:** CASE-001  
**Дата исследования:** [дата]  
**Исполнитель:** [ФИО / подразделение]  
**Объект:** RAW-образ диска Windows 10  
**SHA-256 образа:** [хеш]  
**Цель:** выявление следов компрометации, вредоносной активности и возможных действий APT.

### 1. Основание и цель

Опишите основание проведения исследования, поставленные вопросы и временные рамки.

### 2. Объект и сохранность доказательств

- Имя, формат и размер образа:
- Источник и дата получения:
- SHA-256 до исследования:
- Способ подключения и режим доступа:
- SHA-256 после исследования:
- Результат проверки целостности:
- Ограничения:

### 3. Методика и инструменты

Перечислите инструменты, версии, параметры запуска, источники данных и ошибки обработки.

### 4. Первичный осмотр

- Версия и сборка Windows:
- Системный раздел и часовой пояс:
- Пользовательские профили:
- Доступные журналы и артефакты:
- Ограничения полноты данных:

### 5. Выявленные признаки компрометации

Для каждого признака укажите ID, описание, источник, время, пользователя/процесс, путь, хеш, подтверждающие артефакты, альтернативные объяснения и уровень уверенности.

### 6. Временная шкала

| Время UTC | Событие | Источник | Интерпретация |
|---|---|---|---|
| [время] | [описание] | [артефакт] | [вывод] |

### 7. Механизмы закрепления

Опишите проверенные автозагрузки, службы, задачи планировщика, WMI и другие механизмы. Разделите подтверждённые факты и гипотезы.

### 8. Возможная эксфильтрация

Опишите признаки подготовки данных, сетевые индикаторы, подтверждённые факты передачи и ограничения имеющихся источников.

### 9. IOC

Для каждого IOC приведите тип, значение, источник, время, контекст, уровень уверенности и рекомендуемые действия.

### 10. Выводы

Изложите только выводы, поддержанные доказательствами. Разделите подтверждённые факты, вероятные гипотезы и вопросы, которые не удалось разрешить.

### 11. Рекомендации

- Проверить затронутые учётные записи и системы.
- Выполнить поиск IOC на других узлах.
- Проверить централизованные журналы защиты и сетевые данные.
- Сохранить дополнительные доказательства.
- Локализовать и устранить подтверждённые механизмы компрометации.
- Провести дополнительный анализ при недостаточности данных.

### 12. Приложения

- Хеши образа и извлечённых файлов.
- CSV и логи парсеров.
- Перечень исследованных артефактов.
- Временная шкала.
- IOC.
- Версии инструментов и параметры запуска.

## 18. Официальные ресурсы

- Eric Zimmerman Tools: https://ericzimmerman.github.io/
- KAPE documentation: https://ericzimmerman.github.io/KapeDocs/
- EvtxECmd: https://github.com/EricZimmerman/evtx
- RECmd: https://github.com/EricZimmerman/RECmd
- MFTECmd: https://github.com/EricZimmerman/MFTECmd
- Arsenal Image Mounter: https://arsenalrecon.com/products/arsenal-image-mounter/downloads

**Итоговый принцип:** не делайте вывод о компрометации или принадлежности к APT по одному артефакту. Сопоставляйте независимые источники, документируйте альтернативные объяснения и сохраняйте воспроизводимость каждого шага.
