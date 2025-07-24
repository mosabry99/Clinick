# Maternal-Newborn Images

This folder stores every **PNG** illustration used by maternal-newborn care-plans in the Clinick application.

## Naming convention

1. **File name exactly matches the care-plan title written in Title Case.**  
   • Omit trailing words such as **“Management”**, **“Care”**, or **“Plan.”**  
   • Keep spaces as spaces; **do not** replace them with underscores or hyphens.  
   • Retain clinically relevant punctuation that appears inside the original title (e.g., parentheses).  
2. Use the `.png` extension (lower-case).  
3. Save the file directly in `assets/images/maternal_newborn/`.  
4. When new maternal-newborn care-plans are added (IDs will **begin at mn006** and continue sequentially), create the corresponding image following these rules **before** adding the JSON entry.

Example  
Care-plan title: **“Risk for Postpartum Hemorrhage Management”**  
Image file: `Risk for Postpartum Hemorrhage.png`

---

## Current required images

As of the latest update the maternal-newborn category contains five active plans (IDs **mn001 – mn005**). Ensure **each** plan listed in `care-plans/maternal-newborn-plans.json` has a matching image stored here.  
_Update the table whenever plans are added or removed._

| Care-plan title (trimmed)           | Expected image file                           | Present? |
| ----------------------------------- | --------------------------------------------- | -------- |
| Risk for Postpartum Hemorrhage      | `Risk for Postpartum Hemorrhage.png`          |          |
| Risk for Infection (Postpartum)     | `Risk for Infection (Postpartum).png`         |          |
| Risk for Impaired Parenting         | `Risk for Impaired Parenting.png`             |          |
| Grieving                            | `Grieving.png`                                |          |
| Self-Care Deficit                   | `Self-Care Deficit.png`                       |          |

---

## Contributor checklist

- [ ] Verify the image follows the naming convention above.  
- [ ] Confirm a suitable resolution for both mobile and web (≥ 800 × 600 px recommended).  
- [ ] Optimize file size (< 300 KB preferred) without visible quality loss.  
- [ ] Commit the image **before** referencing it in the care-plan JSON.  
- [ ] Update this README whenever images are added or care-plans are removed.  
- [ ] For any **new** maternal-newborn plan, remember its ID must start at **mn006** or the next available sequential number.

Thank you for helping keep our maternal-newborn media assets organized and consistent!
