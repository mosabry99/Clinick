# Endocrine Images

This folder stores every **PNG** illustration used by endocrine care-plans in the Clinick application.

## Naming convention

1. The file name **matches the care-plan title** written in Title Case.  
   • Omit trailing words such as “Management”, “Care”, or “Plan”.  
   • Keep spaces as spaces; do **not** replace them with underscores or hyphens.  
   • Retain clinically relevant punctuation inside the original title; otherwise remove it.  
2. Use the `.png` extension (lower-case).  
3. Save the file directly in `assets/images/endocrine/`.  
4. When new endocrine care-plans are added (IDs will begin at **en006** and continue sequentially), create the corresponding image using these same rules and add it to this folder **before** updating the JSON file.

Example  
Care-plan title: **“Risk for Unstable Blood Glucose Level Management”**  
Image file: `Risk for Unstable Blood Glucose Level.png`

## Current required images

As of the latest update the endocrine category contains three active plans. Ensure each of the following images is present:

| Care-plan title (trimmed)                              | Expected image file                                     |
| ------------------------------------------------------ | ------------------------------------------------------- |
| Imbalanced Nutrition Less Than Body Requirements       | `Imbalanced Nutrition Less Than Body Requirements.png`  |
| Imbalanced Nutrition More Than Body Requirements       | `Imbalanced Nutrition More Than Body Requirements.png`  |
| Risk for Unstable Blood Glucose Level                  | `Risk for Unstable Blood Glucose Level.png`             |

## Contributor checklist

- [ ] Verify the image follows the naming convention above.  
- [ ] Confirm a suitable resolution for both mobile and web (≥ 800 × 600 px recommended).  
- [ ] Optimize file size (< 300 KB preferred) without visible quality loss.  
- [ ] Commit the image **before** referencing it in the care-plan JSON.  
- [ ] Update this README whenever images are added or care-plans removed.

Thank you for helping keep our media assets organized and consistent!
