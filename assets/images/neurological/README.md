# Neurological Images

This folder stores every **PNG** illustration used by neurological care-plans in the Clinick application.

## Naming convention

1. The file name **matches the care-plan title** written in Title Case.  
   • Omit trailing words such as **“Management”**, **“Care”**, or **“Plan”**.  
   • Keep spaces as spaces; **do not** replace them with underscores or hyphens.  
   • Retain clinically relevant punctuation appearing inside the title; otherwise remove it.  
2. Use the `.png` file extension (lower-case).  
3. Save the file directly inside `assets/images/neurological/`.  
4. When new neurological care-plans are added (IDs will begin at **ne006** and continue sequentially), create the corresponding image following these same rules **before** updating the JSON file.

Example  
Care-plan title: **“Impaired Verbal Communication Management”**  
Image file: `Impaired Verbal Communication.png`

---

## Current required images

As of the latest update the neurological category contains four active plans. Ensure each of the following images is present:

| Care-plan title (trimmed)              | Expected image file                         |
| -------------------------------------- | ------------------------------------------- |
| Acute Confusion                        | `Acute Confusion.png`                       |
| Chronic Confusion                      | `Chronic Confusion.png`                     |
| Impaired Verbal Communication          | `Impaired Verbal Communication.png`         |
| Disturbed Sensory Perception           | `Disturbed Sensory Perception.png`          |

---

## Contributor checklist

- [ ] Verify the image follows the naming convention above.  
- [ ] Confirm a suitable resolution for both mobile and web (≥ 800 × 600 px recommended).  
- [ ] Optimize file size (< 300 KB preferred) without visible quality loss.  
- [ ] Commit the image **before** referencing it in the care-plan JSON.  
- [ ] Update this README whenever images are added or care-plans are removed.

Thank you for keeping our neurological media assets organized and consistent!
