# QEstate

QEstate is a live production post quantum land title registry tool for real property on the Quantova network. It proves the registration, transfer, charge and discharge of land titles, and it lets any third party confirm that history without trusting the party that created it.

QEstate proves records without disclosing them. Title identities and proprietor details stay private on the systems of the party that holds them. Only a salted cryptographic commitment is written to the chain.

## What it records

Each record is a signed envelope of one of four types.

1. register, a registrar records a title with its parcel, tenure, area and first proprietor of record.
2. transfer, the proprietor of record conveys the title to another party.
3. charge, a registrar records a charge or mortgage in favour of a creditor.
4. discharge, a registrar releases a charge by its identifier.

Every record is signed with ML-DSA-65 under FIPS 204 by the party whose role it names, and each later record links to the title it concerns.

## Install

```
npm install @quantovainc/qestate
```

## What a record does not establish

1. It does not show that the stated ownership is lawful. It shows only that the registrar stated it and that the statement existed unchanged at a point in time.
2. It does not identify a natural or legal person. The signer is a chain address, and linking an address to a registrar, proprietor or creditor is a separate attestation.

## License

Apache-2.0 OR MIT
