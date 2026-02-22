---
title: Semantic Edge Types
tags: [concept, enhancement, graph-theory]
---

<!-- ALWAYS_LOAD -->
## Core Facts
- Proposed enhancement to graph contract
- Suggested by [[people/olena]]
- For [[projects/exodus-pp-ua]] knowledge graph
- Provides typed relationships between knowledge entities
- Discussed on 2026-02-22
<!-- /ALWAYS_LOAD -->

## Overview

Semantic edge types are a proposed enhancement to the knowledge graph architecture that would add meaningful, typed relationships between knowledge entities in the graph contract.

## Purpose

Instead of generic wiki-link connections, semantic edge types would allow for explicit relationship types such as:
- "depends on"
- "implements"
- "extends"
- "contradicts"
- "supports"
- etc.

This would enable:
- More precise semantic queries
- Better graph traversal and analysis
- Clearer relationship semantics
- Enhanced knowledge integrity validation

## Context

### Current State
The current [[projects/exodus-pp-ua]] knowledge graph uses wiki-links as the primary connection mechanism, as defined in [[інваріанти_графу_знань]].

### Proposed Enhancement
[[people/olena]] suggested adding semantic edge types to the graph contract to provide richer relationship semantics.

## Related Concepts

- [[concepts/knowledge-graph-architecture]] - Overall architectural approach
- Graph contract - The contract that would be enhanced with semantic edge types

## Discussion

### 2026-02-22
- Proposed by [[people/olena]] in meeting with [[people/garden-owner]]
- Part of knowledge graph architecture discussion for [[projects/exodus-pp-ua]]
