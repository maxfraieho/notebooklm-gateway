// i18n type definitions

export type Locale = 'uk' | 'en' | 'fr' | 'de' | 'it';

export interface Translations {
  // Sidebar
  sidebar: {
    digitalGarden: string;
    home: string;
    graph: string;
    chat: string;
    toggleNavigation: string;
    fileStructure: string;
    explore: string;
    content: string;
  };
  
  // Search
  search: {
    placeholder: string;
    noResults: string;
    clearSearch: string;
  };
  
  // Graph page
  graph: {
    title: string;
    description: string;
    empty: string;
    zoomIn: string;
    zoomOut: string;
    reset: string;
    dragToPan: string;
    notesCount: string;
    connectionsCount: string;
  };
  
  // Local graph legend
  localGraph: {
    current: string;
    linksHere: string;
    linkedFromHere: string;
  };
  
  // Backlinks
  backlinks: {
    linkedFrom: string;
  };
  
  // Tags
  tags: {
    allTags: string;
    tagsInGarden: string;
    tagInGarden: string;
    noTagsYet: string;
    allNotes: string;
    notesTagged: string;
    noteTagged: string;
    noNotesWithTag: string;
    viewAllTags: string;
    updated: string;
  };
  
  // Index / Home
  index: {
    digitalGarden: string;
    description: string;
    allNotes: string;
    notesInGarden: string;
    browseTags: string;
    knowledgeMap: string;
    exploreGraph: string;
    viewGraph: string;
    recentNotes: string;
    connectedThoughts: string;
    connections: string;
    lastUpdated: string;
  };
  
  // Not found
  notFound: {
    title: string;
    message: string;
    returnHome: string;
  };

  // Note page
  notePage: {
    notFoundTitle: string;
    notFoundMessage: string;
    pendingTitle: string;
    pendingMessage: string;
    returnToGarden: string;
  };
  
  // Tag page
  tagPage: {
    noTagSpecified: string;
    returnToGarden: string;
  };
  
  // Common
  common: {
    note: string;
    notes: string;
    tag: string;
    tags: string;
    edit: string;
    close: string;
    copied: string;
    toggleTheme: string;
    language: string;
    cancel: string;
  };

  // Owner menu
  owner: {
    menu: string;
    settings: string;
    zones: string;
    help: string;
    logout: string;
  };

  // Owner Auth
  ownerAuth: {
    loginTitle: string;
    loginDescription: string;
    masterPassword: string;
    enterPassword: string;
    verifying: string;
    unlock: string;
    cancel: string;
    setupTitle: string;
    setupDescription: string;
    createPassword: string;
    confirmPassword: string;
    passwordMinLength: string;
    passwordLengthOk: string;
    passwordsMatch: string;
    passwordsNoMatch: string;
    settingUp: string;
    initializeOwner: string;
    setupHint: string;
  };
  
  // Export Modal
  export: {
    title: string;
    description: string;
    settingsTab: string;
    previewTab: string;
    folderSelection: string;
    selectAll: string;
    folders: string;
    noFolders: string;
    formatSelection: string;
    markdownFormat: string;
    markdownDescription: string;
    jsonFormat: string;
    jsonDescription: string;
    jsonlFormat: string;
    jsonlDescription: string;
    additionalOptions: string;
    includeMetadata: string;
    includeContent: string;
    willExport: string;
    notesFrom: string;
    approximateSize: string;
    cancel: string;
    copy: string;
    copied: string;
    copyToClipboard: string;
    download: string;
    selectAtLeastOne: string;
    exportSuccess: string;
    copySuccess: string;
    copyError: string;
    selectFoldersForExport: string;
    truncatedPreview: string;
  };
  
  // Access Zones
  zones: {
    title: string;
    description: string;
    createNew: string;
    createFirst: string;
    createTitle: string;
    createDescription: string;
    noZones: string;
    zoneName: string;
    zoneNamePlaceholder: string;
    zoneDescription: string;
    zoneDescriptionPlaceholder: string;
    folderSelection: string;
    clearAll: string;
    accessType: string;
    webOnly: string;
    webOnlyDesc: string;
    mcpOnly: string;
    mcpOnlyDesc: string;
    webAndMcp: string;
    webAndMcpDesc: string;
    timeToLive: string;
    custom: string;
    customMinutes: string;
    minutes: string;
    creating: string;
    create: string;
    revoke: string;
    revokeConfirmTitle: string;
    revokeConfirmDescription: string;
    copied: string;
    urlCopied: string;
    qrTitle: string;
    accessUrl: string;
    downloadQR: string;
    qrDownloaded: string;
    qrDownloadError: string;
    // Confidentiality settings
    confidentialitySettings: string;
    requireConsent: string;
    requireConsentDesc: string;
    publicZone: string;
    confidentialZone: string;
  };
  
  // Zone View (Guest Access)
  zoneView: {
    loading: string;
    expired: string;
    expiredDescription: string;
    accessDenied: string;
    invalidZone: string;
    sharedAccess: string;
    availableNotes: string;
    selectNote: string;
    selectNoteDescription: string;
    readOnlyNotice: string;
    selectFoldersForPreview: string;
    noNotesInFolders: string;
    notesPreview: string;
  };
  
  // Access Gate
  accessGate: {
    title: string;
    description: string;
    placeholder: string;
    unlock: string;
    hint: string;
  };
 
   // Editor
   editor: {
     newNote: string;
     editNote: string;
     placeholder: string;
     titlePlaceholder: string;
     save: string;
     cancel: string;
     saving: string;
     saved: string;
     error: string;
     draftFound: string;
     draftRestored: string;
     restoreDraft: string;
     discardDraft: string;
      newNoteHere: string;
     titleRequired: string;
     copiedToClipboard: string;
     preview: string;
     edit: string;
     addTag: string;
     unsavedChanges: string;
     focusMode: string;
     splitView: string;
     saveLocation: string;
     showFolders: string;
     hideFolders: string;
     expandAll: string;
     collapseAll: string;
     rootFolder: string;
     noFolders: string;
     toolbar: {
       bold: string;
       italic: string;
       heading1: string;
       heading2: string;
       heading3: string;
       link: string;
       wikilink: string;
       code: string;
       quote: string;
       bulletList: string;
       numberedList: string;
       table: string;
       strikethrough: string;
       hr: string;
       codeBlock: string;
     };
   };

  // Zone Edit (Guest editing)
  zoneEdit: {
    editing: string;
    proposeEdit: string;
    submitProposal: string;
    proposalSubmitted: string;
    proposalFailed: string;
    yourDetails: string;
    name: string;
    namePlaceholder: string;
    email: string;
    emailPlaceholder: string;
    unsavedChanges: string;
  };

  // Proposals (Owner review)
  proposals: {
    title: string;
    description: string;
    empty: string;
    accepted: string;
    acceptedAutoCommit: string;
    acceptFailed: string;
    rejected: string;
    rejectFailed: string;
    reviewTitle: string;
    submittedBy: string;
    accept: string;
    reject: string;
    acceptedTitle: string;
    copyInstructions: string;
    copyContent: string;
    contentCopied: string;
    rejectTitle: string;
    rejectDescription: string;
    rejectPlaceholder: string;
    minChars: string;
    confirmReject: string;
  };

  // Delegated Zone Consent
  delegatedConsent: {
    title: string;
    summary: string;
    readFull: string;
    checkbox: string;
    continue: string;
    decline: string;
    policyTitle: string;
    policyVersion: string;
  };

  // DRAKON editor UI strings
  drakonEditor: {
    newDiagram: string;
    startHere: string;
    diagramName: string;
    select: string;
    pan: string;
    zoomIn: string;
    zoomOut: string;
    pseudocode: string;
    exportPseudocode: string;
    toggleSilhouette: string;
    createNewDiagram: string;
    diagramId: string;
    diagramIdHint: string;
    createAndEdit: string;
    newDrakon: string;
    enterDiagramId: string;
    enterDiagramName: string;
    diagramNamePlaceholder: string;
    selectFolder: string;
    selectFolderPlaceholder: string;
    newDrakonHere: string;
    savedIn: string;
    accessDenied: string;
    ownerOnly: string;
    returnToGarden: string;
    back: string;
    // Icon toolbar labels
    action: string;
    question: string;
    choice: string;
    caseName: string;
    forLoop: string;
    branchName: string;
    insertion: string;
    comment: string;
    shelf: string;
    simpleInput: string;
    simpleOutput: string;
    input: string;
    output: string;
    process: string;
    timer: string;
    pause: string;
    duration: string;
    groupDuration: string;
    groupDurationRight: string;
    parallel: string;
    parallelBlock: string;
    controlStart: string;
    controlEnd: string;
    endIcon: string;
    link: string;
  };

  // Admin Settings page
  adminSettings: {
    title: string;
    subtitle: string;
    tabSecurity: string;
    tabAccessControl: string;
    tabDiagnostics: string;
    tabAdvanced: string;
    changePassword: string;
    changePasswordDesc: string;
    currentPassword: string;
    currentPasswordPlaceholder: string;
    newPassword: string;
    newPasswordPlaceholder: string;
    confirmNewPassword: string;
    confirmNewPasswordPlaceholder: string;
    passwordChanged: string;
    changePasswordBtn: string;
    securityBestPractices: string;
    tipStrongPassword: string;
    tipChangeRegularly: string;
    tipNeverShare: string;
    accessZones: string;
    accessZonesDesc: string;
    accessZonesInfo: string;
    manageZones: string;
    accessControlInfo: string;
    webAccess: string;
    webAccessDesc: string;
    mcpAccess: string;
    mcpAccessDesc: string;
    ttlAccess: string;
    ttlAccessDesc: string;
    gardenInfo: string;
    gardenInfoDesc: string;
    status: string;
    activeReady: string;
    ownerMode: string;
    enabled: string;
    advancedOptions: string;
    advancedOptionsDesc: string;
    featureMcpGateway: string;
    featureNotebookLM: string;
    featureFolderRestrictions: string;
    featureAccessTTL: string;
  };

  // DRAKON diagram widget labels
  drakon: {
    yes: string;
    no: string;
    end: string;
    exit: string;
    branch: string;
    editContent: string;
    editSecondaryText: string;
    // Context menu items
    copy: string;
    cut: string;
    paste: string;
    delete: string;
    swapYesNo: string;
    addParameters: string;
    insertBranchWithEnd: string;
    insertBranch: string;
    insertBranchLeft: string;
    insertBranchRight: string;
    insertCase: string;
    insertCaseLeft: string;
    insertCaseRight: string;
    addPath: string;
    addPathLeft: string;
    addPathRight: string;
    addVertex: string;
    addRemoveVertex: string;
    sendToBack: string;
    bringToFront: string;
    deletePath: string;
    editUpperText: string;
    editLink: string;
    goToBranch: string;
    increaseMargin: string;
    resetMargin: string;
    flip: string;
    format: string;
    diagramFormat: string;
    changeImage: string;
  };
}

export interface LocaleInfo {
  code: Locale;
  name: string;
  nativeName: string;
}

export const SUPPORTED_LOCALES: LocaleInfo[] = [
  { code: 'uk', name: 'Ukrainian', nativeName: 'Українська' },
  { code: 'en', name: 'English', nativeName: 'English' },
  { code: 'fr', name: 'French', nativeName: 'Français' },
  { code: 'de', name: 'German', nativeName: 'Deutsch' },
  { code: 'it', name: 'Italian', nativeName: 'Italiano' },
];

export const DEFAULT_LOCALE: Locale = 'uk';
