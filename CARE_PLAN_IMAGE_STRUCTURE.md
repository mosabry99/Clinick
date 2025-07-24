# Care-Plan Image Asset Guide

This document standardises **where** care-plan illustrations live and **how** they are named, so that new plans can be added to the Clinick app without confusion.

---

## 1. Directory Layout

```
assets/
└─ images/
   ├─ cardiovascular/
   ├─ critical_care/
   ├─ endocrine/
   ├─ geriatric/
   ├─ integumentary/
   ├─ maternal_newborn/
   ├─ neurological/
   ├─ oncology/
   ├─ orthopedic/
   ├─ palliative_care/
   ├─ pediatric/
   ├─ psychiatric/
   ├─ renal/
   ├─ respiratory/
   └─ surgical/
```

Guidelines  
• Folder names are **all lower-case** and use underscores where natural language has spaces or special characters (e.g. `maternal_newborn`, `palliative_care`).  
• Every specialty that owns care-plan JSON files must have a matching folder, even if no image exists yet.

---

## 2. File-Naming Convention

1. **Start with the care-plan title in Title Case.**  
2. **Remove** trailing descriptors such as “Management”, “Care”, “Plan”, “Nursing Care Plan”, etc.  
3. **Keep spaces**––do **not** replace with underscores or hyphens.  
4. Keep clinically relevant punctuation that appears *inside the title* (e.g. parentheses around disease qualifiers).  
5. Extension is always lower-case `.png`.

Example  

| Care-plan title (in JSON)                              | Image file name                        | Stored at                                                 |
|--------------------------------------------------------|----------------------------------------|-----------------------------------------------------------|
| “Decreased Cardiac Output Management”                  | `Decreased Cardiac Output.png`         | `assets/images/cardiovascular/Decreased Cardiac Output.png` |
| “Risk for Unstable Blood Glucose Level Management”     | `Risk for Unstable Blood Glucose Level.png` | `assets/images/endocrine/Risk for Unstable Blood Glucose Level.png` |

---

## 3. Referencing Images in JSON

Each care-plan object has an `imageUrl` key.  
Value = relative path beginning at `assets/images/…` exactly mirroring the directory structure above.

```jsonc
"imageUrl": "assets/images/renal/Acute Kidney Injury.png"
```

---

## 4. ID System & Image Alignment

All plans now begin at **ID 6** within their category:

| Category              | First valid ID | Example current IDs             |
|-----------------------|----------------|---------------------------------|
| cardiovascular        | `cv006`        | cv006 · cv007 · cv008 …         |
| critical_care         | `cc006`        | cc006 (future)                  |
| endocrine             | `en006`        | en006 · en007 · en008 …         |
| geriatric             | `ng006`        | ng006 (future)                  |
| integumentary         | `in006`        | in006 (future)                  |
| maternal_newborn      | `mn006`        | mn006 (future)                  |
| neurological          | `ne006`        | ne006 · ne007 · ne008 · ne009…  |
| oncology              | `on006`        | on006 (future)                  |
| orthopedic            | `os006`        | os006 (future)                  |
| palliative_care       | `ph006`        | ph006 (future)                  |
| pediatric             | `pd006`        | pd006 (future)                  |
| psychiatric           | `ps006`        | ps006 (future)                  |
| renal                 | `rn006`        | rn006 · rn007 · rn008 …         |
| respiratory           | `rp006`        | rp006 (current)                 |
| surgical              | `sg006`        | sg006 (future)                  |

When adding a new plan **always**:

1. Increment the ID sequentially (`cv009`, `cv010`, …).  
2. Add/verify the PNG following the naming convention.  
3. Update the plan’s `imageUrl` to the correct path.

---

## 5. Contributor Checklist

- [ ] Folder exists for the specialty.  
- [ ] PNG is named exactly per convention and placed in the correct folder.  
- [ ] File size ≤ 300 KB (optimise with lossless compression).  
- [ ] `imageUrl` in JSON matches the file location.  
- [ ] New plan ID continues the sequence starting at 6.  

Thank you for keeping Clinick’s media assets clean and consistent!  
