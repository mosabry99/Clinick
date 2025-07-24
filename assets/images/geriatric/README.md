# Geriatric Images

This folder stores every **PNG** illustration used by **geriatric care-plans** in the Clinick application.

## Naming convention

1. The **file name exactly matches the care-plan title** written in Title Case.  
   • Omit trailing words such as **“Management”**, **“Care”**, or **“Plan”**.  
   • Keep spaces as spaces; **do not** replace them with underscores or hyphens.  
   • Retain clinically relevant punctuation that appears inside the original title (e.g., parentheses).  
2. Use the `.png` extension (lower-case).  
3. Save the file directly in `assets/images/geriatric/`.  
4. When new geriatric care-plans are added (IDs will **begin at ng006** and continue sequentially), create the corresponding image **before** referencing it in the JSON file.

Example  
Care-plan title: **“Risk for Impaired Skin Integrity Management”**  
Image file: `Risk for Impaired Skin Integrity.png`

---

## Current required images

As of the latest update the geriatric category contains five active plans (IDs **ng001 – ng005**).  
Please ensure each active plan listed in `care-plans/geriatric-plans.json` has a matching image here and update the table below whenever plans are added or removed.

| Care-plan title (trimmed) | Expected image file | Present? |
| ------------------------- | ------------------- | -------- |
| _Add rows for each plan_  |                     |          |

---

## Contributor checklist

- [ ] Verify the image follows the naming convention above.  
- [ ] Confirm a suitable resolution for both mobile and web (≥ 800 × 600 px recommended).  
- [ ] Optimize file size (< 300 KB preferred) without visible quality loss.  
- [ ] Commit the image **before** referencing it in the care-plan JSON.  
- [ ] Update this README whenever images are added or care-plans are removed.  
- [ ] For any new geriatric plan, remember its ID must start at **ng006** or the next available sequential number.

Thank you for helping keep our geriatric media assets organized and consistent!
