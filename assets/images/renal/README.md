# Renal Images

This folder stores every **PNG** illustration used by renal care-plans in the Clinick application.

## Naming convention

1. The file name **matches the care-plan title** written in Title Case.  
   • Omit trailing words such as **“Management”**, **“Care”**, or **“Plan”**.  
   • Keep spaces as spaces; **do not** replace them with underscores or hyphens.  
   • Retain clinically relevant punctuation that appears inside the title (e.g., parentheses).  
2. Use the `.png` extension (lower-case).  
3. Save the file directly inside `assets/images/renal/`.  
4. When new renal care-plans are added (IDs will begin at **rn006** and continue sequentially), create the corresponding image using these same rules **before** updating the JSON file.

Example  
Care-plan title: **“Electrolyte Imbalance (Hyperkalemia) Management”**  
Image file: `Electrolyte Imbalance (Hyperkalemia).png`

---

## Current required images

As of the latest update the renal category contains three active plans. Ensure each of the following images is present:

| Care-plan title (trimmed)                     | Expected image file                              |
| --------------------------------------------- | ------------------------------------------------ |
| Acute Kidney Injury                           | `Acute Kidney Injury.png`                        |
| Chronic Kidney Disease                        | `Chronic Kidney Disease.png`                     |
| Electrolyte Imbalance (Hyperkalemia)          | `Electrolyte Imbalance (Hyperkalemia).png`       |

---

## Contributor checklist

- [ ] Verify each image follows the naming convention above.  
- [ ] Confirm suitable resolution for both mobile and web (≥ 800 × 600 px recommended).  
- [ ] Optimize file size (< 300 KB preferred) without visible quality loss.  
- [ ] Commit the image **before** referencing it in the care-plan JSON.  
- [ ] Update this README whenever images are added or care-plans are removed.

Thank you for helping keep our renal media assets organized and consistent!
