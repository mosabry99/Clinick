# Critical Care Images

This folder stores every **PNG** illustration used by critical-care care-plans in the Clinick application.

## Naming convention

1. The file name **matches the care-plan title** written in Title Case.  
   • Omit trailing words such as **“Management”**, **“Care”**, or **“Plan”.**  
   • Keep spaces as spaces; **do not** replace them with underscores or hyphens.  
   • Retain clinically relevant punctuation that appears inside the original title.  
2. Use the `.png` file extension (lower-case).  
3. Save the file directly inside `assets/images/critical_care/`.  
4. When new critical-care care-plans are added (IDs will begin at **cc006** and continue sequentially), create the corresponding image following these same rules **before** updating the JSON file.

Example  
Care-plan title: **“Acute Pain Management”**  
Image file: `Acute Pain.png`

---

## Current required images

As of the latest update the critical-care category contains six active plans. Ensure each of the following images is present:

| Care-plan title (trimmed) | Expected image file      |
| ------------------------- | ------------------------ |
| Acute Pain                | `Acute Pain.png`         |
| Anxiety                   | `Anxiety.png`            |
| Fear                      | `Fear.png`               |
| Risk for Shock            | `Risk for Shock.png`     |
| Risk for Injury           | `Risk for Injury.png`    |
| Risk for Aspiration       | `Risk for Aspiration.png`|

If any plan is removed or a new one is added, update this table accordingly.

---

## Contributor checklist

- [ ] Verify each image follows the naming convention above.  
- [ ] Confirm a suitable resolution for both mobile and web (≥ 800 × 600 px recommended).  
- [ ] Optimize file size (< 300 KB preferred) without visible quality loss.  
- [ ] Commit the image **before** referencing it in the care-plan JSON.  
- [ ] Update this README whenever images are added or care-plans are removed.

Thank you for helping keep our critical-care media assets organized and consistent!
