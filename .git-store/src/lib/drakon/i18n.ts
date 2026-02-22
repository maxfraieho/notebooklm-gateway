// src/lib/drakon/i18n.ts
// Maps DrakonWidget's internal English text strings to i18n translations

import type { Translations } from '@/lib/i18n/types';

/**
 * Creates a translate function for DrakonWidget config.
 * The widget passes English text strings (context menu items) to this function.
 */
export function createDrakonTranslate(drakon: Translations['drakon']): (text: string) => string {
  const map: Record<string, string> = {
    'Copy': drakon.copy,
    'Cut': drakon.cut,
    'Paste': drakon.paste,
    'Delete': drakon.delete,
    'Edit content': drakon.editContent,
    'Swap "Yes" and "No"': drakon.swapYesNo,
    'Add parameters': drakon.addParameters,
    'Insert Branch with End': drakon.insertBranchWithEnd,
    'Insert Branch': drakon.insertBranch,
    'Insert Branch to the left': drakon.insertBranchLeft,
    'Insert Branch to the right': drakon.insertBranchRight,
    'Insert Case': drakon.insertCase,
    'Insert Case to the left': drakon.insertCaseLeft,
    'Insert Case to the right': drakon.insertCaseRight,
    'Add path': drakon.addPath,
    'Add path to the left': drakon.addPathLeft,
    'Add path to the right': drakon.addPathRight,
    'Add vertex': drakon.addVertex,
    'Add remove vertex': drakon.addRemoveVertex,
    'Send to back': drakon.sendToBack,
    'Bring to front': drakon.bringToFront,
    'Delete path': drakon.deletePath,
    'Edit upper text': drakon.editUpperText,
    'Edit link': drakon.editLink,
    'Go to branch': drakon.goToBranch,
    'Increase margin': drakon.increaseMargin,
    'Reset margin': drakon.resetMargin,
    'Flip': drakon.flip,
    'Format': drakon.format,
    'Diagram format': drakon.diagramFormat,
    'Change image': drakon.changeImage,
  };

  return (text: string) => map[text] || text;
}

/**
 * Returns DrakonConfig label properties (yes, no, end, exit, branch)
 */
export function getDrakonLabels(drakon: Translations['drakon']) {
  return {
    yes: drakon.yes,
    no: drakon.no,
    end: drakon.end,
    exit: drakon.exit,
    branch: drakon.branch,
  };
}
