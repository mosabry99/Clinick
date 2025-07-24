# Respiratory Images

This folder stores every **PNG** illustration used by respiratory care-plans in the Clinick application.

## Naming convention

1. The file name **matches the care-plan title** written in Title Case.  
   • Omit trailing words such as **“Management”**, **“Care”**, or **“Plan”**.  
   • Keep spaces as spaces; **do not** replace them with underscores or hyphens.  
   • Retain clinically relevant punctuation that appears inside the original title.  
2. Use the `.png` extension (lower-case).  
3. Save the file directly inside `assets/images/respiratory/`.  
4. When new respiratory care-plans are added (IDs will begin at **rp006** and continue sequentially), create the corresponding image using these rules **before** updating the JSON file.

Example  
Care-plan title: **“Ineffective Breathing Pattern Management”**  
Image file: `Ineffective Breathing Pattern.png`

---

## Current required images

As of the latest update the respiratory category contains one active plan. Ensure the following image is present:

| Care-plan title (trimmed)   | Expected image file               |
| --------------------------- | --------------------------------- |
| Ineffective Airway Clearance | `Ineffective Airway Clearance.png` |

---

## Contributor checklist

- [ ] Verify the image follows the naming convention above.  
- [ ] Confirm a suitable resolution for both mobile and web (≥ 800 × 600 px recommended).  
- [ ] Optimize file size (< 300 KB preferred) without visible quality loss.  
- [ ] Commit the image **before** referencing it in the care-plan JSON.  
- [ ] Update this README whenever images are added or care-plans are removed.

Thank you for keeping our respiratory media assets organized and consistent!
