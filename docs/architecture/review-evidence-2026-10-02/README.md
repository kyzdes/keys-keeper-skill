# Доказательства архитектурного ревью · 2026-10-02

Проверенные исходники: `36df576ba403437d6352add265232bc01601cbae`, Keys Keeper 0.11.1. Эти файлы сопровождают [полный отчёт](/Users/viacheslavkuznetsov/Desktop/Projects/skills/keys-keeper-skill/keys-keeper-tag-directory/docs/architecture/ARCHITECTURE-REVIEW-2026-10-02.md).

## Состав

| Файл | Содержание |
|---|---|
| `review-verification.json` | SHA, версии среды, выбранные тесты, их итог, ссылки CI и границы проверки |
| `local-test-metrics.json` | Фазы и исходы 309 локальных тестов; captured output не сохранялся |
| `ci-manifest.json` | Исходный combined-coverage manifest из CI точного коммита |
| `module-coverage.json` | Выбранные модули из coverage.json того же CI, отдельно line и branch rates |
| `architecture-inventory.json` | Размеры и AST import graph; включает local/TYPE_CHECKING imports |
| `probes.py` | Дополнительные воспроизводящие пробы на изолированных синтетических fixtures |
| `probe-results.json` | 22 наблюдения из probes, включая несколько сценариев одного дефекта |
| `project-idle.json` | Синтетический benchmark: 6 scopes, 3 cycles, retained state |
| `desktop-stats.json` | Синтетический benchmark audit aggregation: 10 000 rows, warm cache, append 10 |
| `release-verification.json` | Опубликованный publisher receipt релиза v0.11.1; не наша независимая проверка установленного приложения |

`probes.py` намеренно утверждает наличие известных проблем в проверенной версии. Успешный запуск этих assertions означает воспроизведение проблемы, а не безопасность продукта. После исправления соответствующая assertion должна перестать проходить; корректную регрессию следует перенести в основную тестовую базу с обратным ожиданием.

Пробы используют MemoryBackend/MemoryAudit, временные каталоги внутри evidence directory, синтетические пароли, отдельный encrypted-file backend и loopback HTTP-сервер на случайном порту. Они не вызывают настоящий OS keychain backend или clipboard. Два дочерних процесса моделируют FIFO hang и crash после backend write; один принудительно завершается по timeout, другой через `os._exit(77)`. История journal cap проверяется временным уменьшением cap с 10 000 до 3 в процессе пробы, без изменения production source.

## Повторный запуск probes

Требуется POSIX-среда; это не Windows ACL-тест. Запускать из checkout исходного коммита, используя его зависимости:

```sh
PYTHONPATH=src .venv/bin/python docs/architecture/review-evidence-2026-10-02/probes.py
```

Команда обновляет только `probe-results.json` рядом со скриптом и создаёт/удаляет свои временные fixtures. Она печатает synthetic-only summary. Повторный запуск может дать другие timings; KDF counts и функциональные assertions важнее абсолютных секунд. Скрипт проверяет SHA импортируемого source checkout перед запуском.

## Проверенные локальные тесты

В `review-verification.json` сохранён список 17 файлов. Прогон использовал изолированный `KEYS_KEEPER_HOME`, synthetic test service и `PYTHONPATH=src`. Локально полный набор заново не исполнялся: полный current-SHA результат проверен через [tests CI](https://github.com/kyzdes/keys-keeper-skill/actions/runs/36997726907), а updater — через [отдельный workflow](https://github.com/kyzdes/keys-keeper-skill/actions/runs/36997726935).

Coverage относится к Python package. Он не доказывает прохождение browser/native UI, Windows DACL security, текущее production/installed state или время работы батареи. `release-verification.json` также остаётся publisher evidence со своими ограничениями.
