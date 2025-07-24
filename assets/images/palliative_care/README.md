# Palliative-Care Images

This folder stores all **PNG** illustrations used by palliative-care care-plans in the Clinick application.

## Naming convention

1. **File name exactly matches the care-plan title written in Title Case.**  
   • Omit trailing words such as **“Management”**, **“Care”**, or **“Plan”.**  
   • Keep spaces as spaces; **do not** replace them with underscores or hyphens.  
   • Retain clinically relevant punctuation that appears inside the original title (e.g., parentheses, colons).  
2. Use the `.png` file extension (lower-case).  
3. Save the file directly in `assets/images/palliative_care/`.  
4. When **new palliative-care plans are added (their IDs will begin at `ph006` and continue sequentially)**, create the corresponding image following these same rules **before** adding the JSON entry.

Example  
Care-plan title: **“Risk for Ineffective Coping Management”**  
Image file: `Risk for Ineffective Coping.png`

---

## Current required images

At present the palliative-care category contains five active plans (IDs **ph001 – ph005**). Ensure **each** plan listed in `care-plans/palliative_care-plans.json` has a matching image stored here.  
_Update the table whenever plans are added or removed._

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
- [ ] For any **new** palliative-care plan, remember its ID must start at **ph006** or the next available sequential number.

Thank you for helping keep our palliative-care media assets organized and consistent!
