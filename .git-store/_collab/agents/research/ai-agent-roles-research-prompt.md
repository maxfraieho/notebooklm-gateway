# Research Prompt: Lightweight AI Agent System with Roles

## Контекст проекту

Розробляється система AI-агентів для Digital Garden (exodus.pp.ua) з інтеграцією в існуючий Cloudflare Worker backend. Система коментарів вже підтримує типи авторів: `human` та `ai-agent` з полем `agentModel`.

## Технічні обмеження

- **Hardware**: Raspberry Pi 3B (1GB RAM, ARM Cortex-A53)
- **CLI**: Claude CLI з Pro акаунтом (обмежене контекстне вікно)
- **Додаткові ресурси**: Replit Core tier
- **Існуюча інфраструктура**: Cloudflare Workers, MinIO S3, KV Storage

## Ключові питання для дослідження

### 1. Архітектура Autoclaude-подібної системи

- Як працює autoclaude (https://github.com/anthropics/anthropic-cookbook/tree/main/misc/prompt_caching)?
- Які патерни можна адаптувати для системи з ролями?
- Як організувати prompt caching для економії токенів на RPi?
- Чи є альтернативи autoclaude для Claude CLI?

### 2. Легкі векторні бази даних для Raspberry Pi

Порівняти за критеріями: RAM usage, швидкість, простота розгортання:

- **SQLite + sqlite-vss** (векторний пошук на SQLite)
- **Chroma** (lightweight, Python)
- **LanceDB** (serverless, embeddable)
- **Qdrant** (Rust, можливо занадто важкий?)
- **txtai** (Python, all-in-one)
- **FAISS** (Facebook, потребує numpy)

Питання:
- Який мінімальний RAM для 10K-100K документів?
- Які embedding моделі працюють на ARM (ONNX, quantized)?
- Чи можна використати CPU-only inference?

### 3. Ролі AI-агентів

Описати архітектуру для ролей:

#### Архіваріус (Archivist)
- Пише резюме статей
- Створює есе на основі кількох джерел
- Формує дайджести за період

#### Технічний письменник (Technical Writer)
- Генерує технічну документацію
- Пояснює код та архітектури
- Створює README, ADR (Architecture Decision Records)

#### Архітектор (Architect)
- Аналізує масиви даних
- Проектує системні архітектури
- Створює діаграми (Mermaid)

#### Інші потенційні ролі
- Редактор (перевірка граматики, стилю)
- Перекладач (мультимовність)
- Дослідник (пошук та синтез інформації)

Питання:
- Як структурувати system prompts для кожної ролі?
- Як передавати контекст між ролями (pipeline)?
- Чи потрібен "orchestrator" агент?

### 4. Інтеграція з Digital Garden

Як агенти взаємодіють з існуючою системою:

```
[Claude CLI + Role] 
    ↓ (generates content)
[Local Script]
    ↓ (POST to API)
[Cloudflare Worker]
    ↓ (stores)
[MinIO + KV]
    ↓ (displays)
[Lovable Frontend]
```

Питання:
- API endpoints для агентів (batch processing)?
- Формат submission від агента (markdown + metadata)?
- Модерація AI-контенту (auto-approve для довірених агентів)?

### 5. Управління контекстом

Стратегії для обмеженого контекстного вікна:

- **RAG (Retrieval-Augmented Generation)**: пошук релевантних фрагментів
- **Summarization chains**: стиснення великих документів
- **Sliding window**: обробка частинами
- **Memory systems**: зберігання ключових фактів

Питання:
- Оптимальний розмір chunk для embedding?
- Як балансувати precision vs recall?
- Локальні embedding моделі для RPi?

### 6. Deployment на Replit

Можливості Replit Core:
- Always-on deployments
- Background workers
- PostgreSQL (з pgvector?)
- Secrets management

Питання:
- Чи краще vector DB на Replit, а Claude CLI на RPi?
- Hybrid architecture: RPi для inference, Replit для storage?
- Latency considerations?

### 7. Конкретні імплементації для порівняння

Знайти та порівняти:

1. **Autoclaude** - оригінальний проект
2. **Claude Engineer** - https://github.com/Doriandarko/claude-engineer
3. **Aider** - https://github.com/paul-gauthier/aider
4. **Open Interpreter** - https://github.com/OpenInterpreter/open-interpreter
5. **GPT-Engineer** - https://github.com/gpt-engineer-org/gpt-engineer

## Очікуваний результат

1. **Рекомендована архітектура** для RPi + Replit hybrid
2. **Вибір vector DB** з обґрунтуванням
3. **Структура ролей** з прикладами prompts
4. **API design** для інтеграції агентів
5. **Приклад workflow** для кожної ролі
6. **Оцінка ресурсів** (RAM, storage, API calls/month)

## Формат відповіді

Структурована відповідь з:
- Таблицями порівняння
- Діаграмами архітектури (Mermaid)
- Прикладами коду (Python, bash)
- Посиланнями на документацію
- Оцінкою складності імплементації (1-5)

---

*Цей промт створено для дослідження на Gemini Pro та Perplexity Pro з метою синтезу оптимального рішення для Digital Garden AI Agent System.*
