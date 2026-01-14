# SentinelDLP v1.3.0

**Release Date:** Feature Release
**Status:** Stable
**Feature:** FR-002 - Admin Configuration Panel

## Overview

Major feature release introducing a comprehensive admin configuration panel for customizing SentinelDLP behavior without code changes.

## New Features

### Admin Configuration Panel (FR-002)

A complete settings interface accessible via the Settings navigation item.

#### Sensitivity Thresholds
- Configurable score thresholds for LOW/MEDIUM/HIGH/CRITICAL classifications
- Default values: LOW (0-25), MEDIUM (26-50), HIGH (51-75), CRITICAL (76-100)
- Real-time threshold preview

#### File Handling Settings
- Maximum file size limit (configurable, default 500MB)
- Allowed file extensions management
- File type whitelist/blacklist

#### Department Configuration
- Enable/disable specific departments
- Custom department labels
- Department priority ordering

#### Analysis Settings
- Confidence threshold adjustment
- Enable/disable specific sensitivity dimensions
- Custom regulatory framework selection

#### System Settings
- API timeout configuration
- Retry policy settings
- Debug mode toggle

### Settings Persistence
- Settings stored in browser localStorage
- Export/import configuration as JSON
- Reset to defaults option

## UI Components

### SettingsPage Component
- Tabbed interface for organized settings
- Real-time validation
- Save/cancel confirmation dialogs

### Settings Navigation
- New "Settings" item in navigation bar
- Gear icon indicator
- Active state styling

## Changes from v1.2.0

### Added
- Complete SettingsPage React component
- Settings state management
- Configuration export/import
- Input validation for all settings

### Modified
- Navigation component with Settings link
- Analysis engine respects configured thresholds

## Configuration Schema

```javascript
{
  thresholds: {
    low: { min: 0, max: 25 },
    medium: { min: 26, max: 50 },
    high: { min: 51, max: 75 },
    critical: { min: 76, max: 100 }
  },
  fileHandling: {
    maxSizeMB: 500,
    allowedExtensions: [".txt", ".pdf", ".docx", ...]
  },
  departments: {
    enabled: ["HR", "Finance", "Legal", ...],
    labels: { ... }
  },
  analysis: {
    confidenceThreshold: 0.7,
    enabledDimensions: [...]
  }
}
```

## Upgrade Notes

- Settings will initialize with defaults on first load
- Existing deployments unaffected (graceful fallback)
- No database migration required
