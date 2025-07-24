# Orthopedic Images

This folder stores every **PNG** illustration used by orthopedic care-plans in the Clinick application.

## Naming convention
1. **File name exactly matches the care-plan title written in Title Case.**  
   • Omit trailing words such as **“Management”**, **“Care”**, or **“Plan”**.  
   • Keep spaces as spaces; **do not** replace them with underscores or hyphens.  
   • Retain any clinically relevant punctuation that appears inside the original title (e.g., parentheses, colons).  
2. Use the `.png` extension (lower-case).  
3. Save the file directly in `assets/images/orthopedic/`.  
4. When **new orthopedic care-plans are added, their IDs must begin at `os006` and continue sequentially**; create the corresponding image _before_ updating the JSON file.

Example  
Care-plan title: **“Impaired Physical Mobility Management”**  
Image file: `Impaired Physical Mobility.png`

---

## Current required images
The orthopedic category currently contains five active plans (`os001 – os005`). Ensure **each** plan listed in `care-plans/orthopedic-plans.json` has a matching image stored here.

_Update the table whenever plans are added or removed._

| Care-plan title (trimmed)      | Expected image file                         | Present? |
| ------------------------------ | ------------------------------------------- | -------- |
| _Add rows for each plan_       |                                             |          |

---

## Contributor checklist
- [ ] Verify the image follows the naming convention above.  
- [ ] Confirm a suitable resolution for both mobile and web (≥ 800 × 600 px recommended).  
- [ ] Optimize file size (< 300 KB preferred) without visible quality loss.  
- [ ] Commit the image **before** referencing it in the care-plan JSON.  
- [ ] Update this README whenever images are added or care-plans removed.  
- [ ] For any **new** orthopedic plan, remember its ID must start at **os006** or the next available sequential number.

Thank you for helping keep our orthopedic media assets organized and consistent!
