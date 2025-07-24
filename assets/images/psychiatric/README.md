# Psychiatric Images

This folder stores every **PNG** illustration used by psychiatric care-plans in the Clinick application.

---

## Naming convention  

1. **File name exactly matches the care-plan title written in Title Case.**  
   • Omit trailing words such as **“Management”**, **“Care”**, or **“Plan.”**  
   • Keep spaces as spaces – **do not** replace them with underscores or hyphens.  
   • Retain clinically relevant punctuation that appears **inside** the original title (e.g., parentheses, colons).  
2. Use the `.png` file extension (lower-case).  
3. Save the file directly inside `assets/images/psychiatric/`.  
4. When new psychiatric care-plans are added, their IDs must **begin at `ps006` and continue sequentially**; create the corresponding image **before** updating the JSON file.

### Example  
Care-plan title: **“Ineffective Coping Management”**  
Image file: `Ineffective Coping.png`

---

## Current required images

As of the latest update the psychiatric category contains five active plans (IDs **ps001 – ps005**).  
Ensure **each** plan listed in `care-plans/psychiatric-plans.json` has a matching image stored here.

| Care-plan title (trimmed)        | Expected image file                    | Present? |
| -------------------------------- | -------------------------------------- | -------- |
| Anxiety                          | `Anxiety.png`                          |          |
| Fear                             | `Fear.png`                             |          |
| Disturbed Thought Processes      | `Disturbed Thought Processes.png`      |          |
| Ineffective Coping               | `Ineffective Coping.png`               |          |
| Grieving                         | `Grieving.png`                         |          |

_Update this table whenever plans are added or removed._

---

## Contributor checklist

- [ ] Verify the image follows the naming convention above.  
- [ ] Confirm a suitable resolution for both mobile and web (≥ 800 × 600 px recommended).  
- [ ] Optimize file size (< 300 KB preferred) without visible quality loss.  
- [ ] Commit the image **before** referencing it in the care-plan JSON.  
- [ ] Update this README whenever images are added or care-plans are removed.  
- [ ] For any **new** psychiatric plan, remember its ID must start at **ps006** or the next available sequential number.

Thank you for helping keep our psychiatric media assets organized and consistent!
