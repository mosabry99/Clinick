# Surgical Images

This folder stores every **PNG** illustration used by surgical care-plans in the Clinick application.

---

## Naming convention  

1. **File name exactly matches the care-plan title written in Title Case.**  
   • Omit trailing words such as **“Management”**, **“Care”**, or **“Plan.”**  
   • Keep spaces as spaces — **do not** replace them with underscores or hyphens.  
   • Retain clinically relevant punctuation that appears *inside* the original title (e.g., parentheses, colons).  
2. Use the `.png` file extension (lower-case).  
3. Save the file directly inside `assets/images/surgical/`.  
4. When new surgical care-plans are added, their IDs must **begin at `sg006` and continue sequentially**; create the corresponding image **before** referencing it in the JSON file.

### Example  
Care-plan title: **“Disturbed Body Image Management”**  
Image file: `Disturbed Body Image.png`

---

## Current required images

As of the latest update the surgical category contains five active plans (IDs **sg001 – sg005**).  
Please ensure **each** plan listed in `care-plans/surgical-plans.json` has a matching image stored here.  
_Update the table whenever plans are added or removed._

| Care-plan title (trimmed)           | Expected image file                         | Present? |
| ----------------------------------- | ------------------------------------------- | -------- |
| _Add rows for each surgical plan_   |                                             |          |

---

## Contributor checklist

- [ ] Verify the image follows the naming convention above.  
- [ ] Confirm a suitable resolution for both mobile and web (≥ 800 × 600 px recommended).  
- [ ] Optimize file size (< 300 KB preferred) without visible quality loss.  
- [ ] Commit the image **before** referencing it in the care-plan JSON.  
- [ ] Update this README whenever images are added or care-plans are removed.  
- [ ] For any **new** surgical plan, remember its ID must start at **sg006** or the next available sequential number.

Thank you for helping keep our surgical media assets organized and consistent!
