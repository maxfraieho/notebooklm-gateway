// Policy Page
// Displays localized confidentiality terms for Delegated Zones

import { useLocale } from '@/hooks/useLocale';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { ArrowLeft, Shield } from 'lucide-react';
import { Link } from 'react-router-dom';
import { ThemeToggle } from '@/components/garden/ThemeToggle';
import { LanguageSwitcher } from '@/components/garden/LanguageSwitcher';

const POLICY_VERSION = '2026-02-06';

// Policy content by locale
const policyContent: Record<string, string> = {
  uk: `# Делеговані зони: умови доступу та конфіденційність

Ця Делегована зона ("Зона") створена власником контенту ("Власник") для надання обмеженого доступу до вибраних матеріалів (нотаток, статей, файлів, метаданих) ("Матеріали"). Доступ до Матеріалів надається вам ("Користувач") лише за умови прийняття цих правил.

## 1. Прийняття умов

Натискаючи "Погоджуюсь" (або іншу аналогічну кнопку/прапорець), ви підтверджуєте, що:

- прочитали та зрозуміли ці умови;
- маєте повноваження прийняти їх (як фізична особа або від імені організації);
- зобов'язуєтесь їх дотримуватись.

Якщо ви не погоджуєтесь — не відкривайте Матеріали та не використовуйте код/посилання доступу.

## 2. Конфіденційність та нерозповсюдження

**2.1.** "Конфіденційна інформація" — будь-які Матеріали, позначені як конфіденційні, а також будь-які дані, які за своєю природою або контекстом доступу мають розглядатися як конфіденційні.

**2.2.** Ви зобов'язуєтесь:

- не розкривати, не публікувати, не передавати та не надавати доступ до конфіденційної інформації третім особам;
- не копіювати і не відтворювати Матеріали понад мінімально необхідне для дозволеної мети;
- не робити скриншоти/записи екрана/експорт без прямого дозволу Власника (якщо інше не дозволено в Зоні явно).

**2.3.** Дозволена мета доступу: ознайомлення та використання Матеріалів виключно для цілей, визначених Власником (наприклад: спільна робота, консультація, рев'ю, оцінка, навчання).

## 3. Відкриті розділи

Власник може позначити частину Матеріалів як "Відкриті". Такі розділи можуть бути доступні без додаткового підтвердження конфіденційності, але інші положення (зокрема про інтелектуальну власність та обмеження відповідальності) все одно застосовуються.

## 4. Інтелектуальна власність

Усі права на Матеріали належать Власнику або правовласникам. Вам не передаються жодні права власності. Ви отримуєте лише тимчасовий, відкличний, обмежений доступ відповідно до цих умов.

## 5. Заборонені дії

Забороняється:

- обходити або намагатися обходити механізми доступу (коди, токени, TTL, обмеження);
- передавати посилання/QR-код/код доступу іншим особам, якщо це не дозволено Власником;
- здійснювати автоматизований збір даних (scraping), масове завантаження, індексацію;
- використовувати Матеріали для створення конкуруючого продукту або для порушення прав третіх осіб.

## 6. Термін дії та відкликання

Доступ може бути обмежений у часі (TTL) та/або відкликаний Власником у будь-який момент. Після завершення доступу ви зобов'язуєтесь припинити використання Матеріалів і, за запитом Власника, видалити локальні копії (якщо такі створювались).

## 7. Винятки

Зобов'язання конфіденційності не застосовуються до інформації, яка:

- стала загальнодоступною не через порушення цих умов;
- була законно отримана від третьої сторони без обмежень;
- була відома вам до доступу до Зони та це можна підтвердити.

## 8. Відмова від гарантій та обмеження відповідальності

Матеріали надаються "як є". Власник не гарантує повноту, точність або придатність Матеріалів для конкретної мети. У межах, дозволених законом, Власник не несе відповідальності за будь-які непрямі збитки або втрату даних/прибутку.

## 9. Обробка даних та журнали подій

Для забезпечення безпеки доступу можуть зберігатися технічні журнали (наприклад: факт прийняття умов, час, зона, IP/ідентифікатори пристрою у скороченому або хешованому вигляді). Ці дані використовуються для аудиту доступу та захисту від зловживань.

## 10. Контакти та зміни умов

Власник може оновлювати ці умови. Якщо ви продовжуєте користуватись Зоною після оновлення — це означає прийняття нової редакції. Для питань звертайтесь до Власника через канал, яким вам надано доступ.`,

  en: `# Delegated Zones: Access & Confidentiality Terms

This Delegated Zone ("Zone") is created by the content owner ("Owner") to provide limited access to selected materials (notes, articles, files, metadata) ("Materials"). Access is granted to you ("User") only if you accept these terms.

## 1. Acceptance

By clicking "I Agree" (or an equivalent action), you confirm that you:

- have read and understood these terms;
- have authority to accept them (as an individual or on behalf of an organization);
- will comply with them.

If you do not agree, do not open the Materials and do not use the access link/QR/code.

## 2. Confidentiality & Non-Disclosure

**2.1.** "Confidential Information" means any Materials marked as confidential and any information that should reasonably be treated as confidential given its nature or the context of access.

**2.2.** You agree to:

- not disclose, publish, share, or provide access to Confidential Information to any third party;
- not copy or reproduce the Materials beyond what is strictly necessary for the permitted purpose;
- not take screenshots/screen recordings/exports without the Owner's explicit permission (unless the Zone explicitly allows it).

**2.3.** Permitted purpose: to review and use the Materials solely for the purpose defined by the Owner (e.g., collaboration, consultation, review, evaluation, learning).

## 3. Public Sections

The Owner may designate some Materials as "Public". Such sections may be accessible without an additional confidentiality confirmation, but other provisions (including IP and liability) still apply.

## 4. Intellectual Property

All rights in the Materials remain with the Owner or respective rightsholders. No ownership rights are transferred. You receive only a temporary, revocable, limited access under these terms.

## 5. Prohibited Actions

You must not:

- bypass or attempt to bypass access controls (codes, tokens, TTL, restrictions);
- share the access link/QR/code with others unless explicitly allowed by the Owner;
- perform automated data collection (scraping), bulk downloading, indexing;
- use the Materials to build a competing product or to infringe third-party rights.

## 6. Term & Revocation

Access may be time-limited (TTL) and/or revoked by the Owner at any time. After access ends, you must stop using the Materials and, upon request, delete any local copies (if created).

## 7. Exceptions

Confidentiality obligations do not apply to information that:

- becomes public through no breach of these terms;
- is lawfully received from a third party without restrictions;
- was already known to you before access and can be evidenced.

## 8. Disclaimer & Limitation of Liability

Materials are provided "as is". The Owner makes no warranties regarding completeness, accuracy, or fitness for a particular purpose. To the maximum extent permitted by law, the Owner is not liable for indirect damages or loss of data/profit.

## 9. Data Processing & Logs

To protect access, technical logs may be stored (e.g., acceptance event, time, zone, IP/device identifiers in truncated or hashed form). Logs are used for audit and abuse prevention.

## 10. Updates & Contact

The Owner may update these terms. Continued use after an update constitutes acceptance of the revised terms. Contact the Owner via the channel used to share access.`,

  fr: `# Zones déléguées : conditions d'accès et confidentialité

Cette Zone déléguée (« Zone ») est créée par le propriétaire du contenu (« Propriétaire ») afin de fournir un accès limité à certains contenus (notes, articles, fichiers, métadonnées) (« Contenus »). L'accès vous est accordé (« Utilisateur ») uniquement si vous acceptez les présentes conditions.

## 1. Acceptation

En cliquant sur « J'accepte » (ou action équivalente), vous confirmez :

- avoir lu et compris ces conditions ;
- disposer de l'autorité nécessaire pour les accepter (à titre personnel ou pour une organisation) ;
- vous engager à les respecter.

Si vous refusez, n'ouvrez pas les Contenus et n'utilisez pas le lien/QR/code d'accès.

## 2. Confidentialité et non-divulgation

**2.1.** Les « Informations confidentielles » désignent tout Contenu marqué confidentiel et toute information qui, par sa nature ou le contexte, doit raisonnablement être considérée comme confidentielle.

**2.2.** Vous vous engagez à :

- ne pas divulguer, publier, partager ni donner accès aux Informations confidentielles à des tiers ;
- ne pas copier/reproduire les Contenus au-delà du strict nécessaire à l'objectif autorisé ;
- ne pas effectuer de captures d'écran/enregistrements/exportations sans l'autorisation expresse du Propriétaire (sauf autorisation explicite dans la Zone).

**2.3.** Objectif autorisé : consulter et utiliser les Contenus uniquement pour l'objectif défini par le Propriétaire (collaboration, consultation, revue, évaluation, apprentissage, etc.).

## 3. Sections publiques

Le Propriétaire peut désigner certaines parties comme « Publiques ». Elles peuvent être accessibles sans confirmation supplémentaire, mais les autres dispositions (PI, responsabilité) s'appliquent.

## 4. Propriété intellectuelle

Tous les droits sur les Contenus restent au Propriétaire ou aux ayants droit. Aucun droit de propriété n'est transféré. Vous bénéficiez uniquement d'un accès temporaire, révocable et limité.

## 5. Actions interdites

Il est interdit de :

- contourner ou tenter de contourner les contrôles d'accès (codes, tokens, TTL, restrictions) ;
- partager le lien/QR/code d'accès sauf autorisation expresse ;
- effectuer une collecte automatisée (scraping), un téléchargement massif, une indexation ;
- utiliser les Contenus pour créer un produit concurrent ou porter atteinte à des droits de tiers.

## 6. Durée et révocation

L'accès peut être limité dans le temps (TTL) et/ou révoqué à tout moment. Après expiration, vous devez cesser toute utilisation et, sur demande, supprimer les copies locales éventuelles.

## 7. Exceptions

Les obligations de confidentialité ne s'appliquent pas si l'information :

- devient publique sans violation ;
- est reçue légalement d'un tiers sans restriction ;
- était déjà connue avant l'accès et peut être prouvée.

## 8. Absence de garantie et limitation de responsabilité

Les Contenus sont fournis « en l'état ». Aucune garantie n'est donnée. Dans la limite permise par la loi, le Propriétaire n'est pas responsable des dommages indirects ou pertes de données/profits.

## 9. Données et journaux

Des journaux techniques peuvent être conservés (acceptation, horodatage, zone, identifiants IP/appareil tronqués ou hachés) à des fins d'audit et de prévention des abus.

## 10. Mises à jour et contact

Les conditions peuvent être mises à jour. L'utilisation après mise à jour vaut acceptation. Contactez le Propriétaire via le canal de partage.`,

  de: `# Delegierte Zonen: Zugriffs- und Vertraulichkeitsbedingungen

Diese Delegierte Zone („Zone") wird vom Inhaltsinhaber („Inhaber") erstellt, um einen eingeschränkten Zugriff auf ausgewählte Materialien (Notizen, Artikel, Dateien, Metadaten) („Materialien") zu gewähren. Zugriff erhältst du („Nutzer") nur, wenn du diese Bedingungen akzeptierst.

## 1. Zustimmung

Durch Klicken auf „Ich stimme zu" (oder eine gleichwertige Handlung) bestätigst du, dass du:

- diese Bedingungen gelesen und verstanden hast;
- berechtigt bist, sie anzunehmen (privat oder im Namen einer Organisation);
- sie einhalten wirst.

Wenn du nicht zustimmst, öffne die Materialien nicht und nutze keinen Zugangslink/QR/Code.

## 2. Vertraulichkeit & Nichtweitergabe

**2.1.** „Vertrauliche Informationen" sind alle als vertraulich gekennzeichneten Materialien sowie alle Informationen, die aufgrund ihrer Natur oder des Kontexts als vertraulich zu behandeln sind.

**2.2.** Du verpflichtest dich:

- vertrauliche Informationen nicht offenzulegen, zu veröffentlichen, zu teilen oder Dritten zugänglich zu machen;
- Materialien nur in dem Umfang zu kopieren/zu reproduzieren, wie es für den erlaubten Zweck zwingend erforderlich ist;
- keine Screenshots/Screen-Recordings/Exporte ohne ausdrückliche Zustimmung des Inhabers anzufertigen (sofern nicht ausdrücklich erlaubt).

**2.3.** Erlaubter Zweck: Nutzung ausschließlich für den vom Inhaber definierten Zweck (z. B. Zusammenarbeit, Beratung, Review, Bewertung, Lernen).

## 3. Öffentliche Abschnitte

Der Inhaber kann Teile als „Öffentlich" markieren. Diese können ohne zusätzliche Bestätigung zugänglich sein; andere Regelungen (IP, Haftung) gelten weiterhin.

## 4. Geistiges Eigentum

Alle Rechte verbleiben beim Inhaber bzw. Rechteinhabern. Es werden keine Eigentumsrechte übertragen. Du erhältst nur einen zeitlich begrenzten, widerruflichen, eingeschränkten Zugriff.

## 5. Verbotene Handlungen

Untersagt ist:

- das Umgehen/Versuchen des Umgehens von Zugriffskontrollen (Codes, Tokens, TTL);
- das Weitergeben von Link/QR/Code ohne Erlaubnis;
- automatisiertes Sammeln (Scraping), Massen-Downloads, Indexierung;
- Nutzung zur Erstellung eines konkurrierenden Produkts oder zur Verletzung von Rechten Dritter.

## 6. Laufzeit & Widerruf

Zugriff kann zeitlich begrenzt (TTL) und jederzeit widerrufen werden. Nach Ende des Zugriffs ist die Nutzung einzustellen; lokale Kopien sind auf Anfrage zu löschen.

## 7. Ausnahmen

Keine Vertraulichkeitspflicht für Informationen, die:

- ohne Vertragsverletzung öffentlich werden;
- rechtmäßig von Dritten ohne Beschränkung erhalten wurden;
- bereits vorher bekannt waren und nachweisbar sind.

## 8. Haftungsausschluss

Bereitstellung „wie gesehen". Keine Gewährleistung. Soweit gesetzlich zulässig, keine Haftung für indirekte Schäden oder Daten-/Gewinnverluste.

## 9. Daten & Protokolle

Technische Logs können gespeichert werden (Zustimmung, Zeitpunkt, Zone, gekürzte/gehäschte IP-/Geräte-IDs) für Audit und Missbrauchsprävention.

## 10. Änderungen & Kontakt

Bedingungen können aktualisiert werden. Weitere Nutzung gilt als Zustimmung. Kontakt über den Freigabekanal.`,

  it: `# Zone delegate: condizioni di accesso e riservatezza

Questa Zona delegata ("Zona") è creata dal proprietario dei contenuti ("Proprietario") per fornire accesso limitato a materiali selezionati (note, articoli, file, metadati) ("Materiali"). L'accesso è concesso a te ("Utente") solo se accetti i presenti termini.

## 1. Accettazione

Facendo clic su "Accetto" (o azione equivalente), confermi di:

- aver letto e compreso i termini;
- avere l'autorità per accettarli (come individuo o per conto di un'organizzazione);
- impegnarti a rispettarli.

Se non accetti, non aprire i Materiali e non usare link/QR/codice di accesso.

## 2. Riservatezza e non divulgazione

**2.1.** "Informazioni riservate" significa qualsiasi Materiale contrassegnato come riservato e qualsiasi informazione che, per natura o contesto, debba ragionevolmente essere trattata come riservata.

**2.2.** Ti impegni a:

- non divulgare, pubblicare, condividere o concedere accesso a terzi alle Informazioni riservate;
- non copiare o riprodurre i Materiali oltre lo stretto necessario per lo scopo consentito;
- non effettuare screenshot/registrazioni/export senza autorizzazione esplicita (salvo permesso esplicito nella Zona).

**2.3.** Scopo consentito: consultare e utilizzare i Materiali esclusivamente per lo scopo definito dal Proprietario (collaborazione, consulenza, revisione, valutazione, apprendimento).

## 3. Sezioni pubbliche

Il Proprietario può indicare parti come "Pubbliche". Possono essere accessibili senza ulteriore conferma, ma le altre clausole (IP, responsabilità) restano valide.

## 4. Proprietà intellettuale

Tutti i diritti restano al Proprietario o ai titolari. Nessun diritto di proprietà viene trasferito. Ottieni solo accesso temporaneo, revocabile e limitato.

## 5. Azioni vietate

È vietato:

- aggirare o tentare di aggirare i controlli di accesso (codici, token, TTL);
- condividere link/QR/codice senza autorizzazione;
- scraping, download massivi, indicizzazione automatica;
- usare i Materiali per creare un prodotto concorrente o violare diritti di terzi.

## 6. Durata e revoca

L'accesso può essere limitato nel tempo (TTL) e/o revocato in qualsiasi momento. Dopo la scadenza, devi cessare l'uso e, su richiesta, eliminare eventuali copie locali.

## 7. Eccezioni

Gli obblighi non si applicano a informazioni che:

- diventano pubbliche senza violazione;
- sono ricevute lecitamente da terzi senza restrizioni;
- erano già note prima dell'accesso e sono dimostrabili.

## 8. Esclusione di garanzie e limitazione di responsabilità

Materiali forniti "così come sono". Nessuna garanzia. Nei limiti di legge, nessuna responsabilità per danni indiretti o perdita di dati/profitti.

## 9. Dati e log

Possono essere conservati log tecnici (accettazione, data/ora, zona, IP/device troncati o hashati) per audit e prevenzione abusi.

## 10. Aggiornamenti e contatto

I termini possono essere aggiornati. L'uso continuato implica accettazione. Contatta il Proprietario tramite il canale di condivisione.`,
};

export default function PolicyPage() {
  const { locale, t } = useLocale();
  
  const content = policyContent[locale] || policyContent.en;
  
  // Simple markdown to JSX converter for headings and paragraphs
  const renderContent = () => {
    const lines = content.split('\n');
    const elements: JSX.Element[] = [];
    let key = 0;
    
    for (const line of lines) {
      if (line.startsWith('# ')) {
        // Skip the main title, we render it separately
        continue;
      } else if (line.startsWith('## ')) {
        elements.push(
          <h2 key={key++} className="text-lg font-semibold mt-6 mb-3">
            {line.replace('## ', '')}
          </h2>
        );
      } else if (line.startsWith('**') && line.endsWith('**')) {
        elements.push(
          <p key={key++} className="font-medium mt-3 mb-1">
            {line.replace(/\*\*/g, '')}
          </p>
        );
      } else if (line.startsWith('- ')) {
        elements.push(
          <li key={key++} className="ml-4 text-muted-foreground">
            {line.replace('- ', '')}
          </li>
        );
      } else if (line.trim()) {
        // Handle inline bold
        const parts = line.split(/(\*\*[^*]+\*\*)/g);
        const formattedParts = parts.map((part, i) => {
          if (part.startsWith('**') && part.endsWith('**')) {
            return <strong key={i}>{part.slice(2, -2)}</strong>;
          }
          return part;
        });
        elements.push(
          <p key={key++} className="text-muted-foreground mb-2">
            {formattedParts}
          </p>
        );
      }
    }
    
    return elements;
  };

  return (
    <div className="min-h-screen bg-background flex flex-col">
      {/* Header */}
      <header className="sticky top-0 z-[60] bg-card/95 backdrop-blur-sm border-b border-border shadow-sm">
        <div className="max-w-4xl mx-auto px-4 h-14 flex items-center justify-between gap-4">
          <Button asChild variant="ghost" size="sm">
            <Link to="/">
              <ArrowLeft className="h-4 w-4 mr-2" />
              {t.notFound.returnHome}
            </Link>
          </Button>
          <div className="flex items-center gap-2">
            <LanguageSwitcher />
            <ThemeToggle />
          </div>
        </div>
      </header>

      {/* Content */}
      <main className="flex-1 container max-w-4xl mx-auto px-4 py-8">
        <Card>
          <CardHeader>
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 rounded-full bg-primary/10">
                <Shield className="h-6 w-6 text-primary" />
              </div>
              <div className="flex-1">
                <CardTitle className="text-xl">
                  {t.delegatedConsent.policyTitle}
                </CardTitle>
              </div>
              <Badge variant="secondary">
                {t.delegatedConsent.policyVersion}: {POLICY_VERSION}
              </Badge>
            </div>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[calc(100vh-280px)] pr-4">
              <div className="prose prose-sm dark:prose-invert max-w-none">
                {renderContent()}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}
