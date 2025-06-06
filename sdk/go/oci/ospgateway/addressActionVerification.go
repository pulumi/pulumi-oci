// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package ospgateway

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Address Action Verification resource in Oracle Cloud Infrastructure Osp Gateway service.
//
// # Verify address
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/ospgateway"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := ospgateway.NewAddressActionVerification(ctx, "test_address_action_verification", &ospgateway.AddressActionVerificationArgs{
//				CompartmentId:        pulumi.Any(compartmentId),
//				OspHomeRegion:        pulumi.Any(addressActionVerificationOspHomeRegion),
//				AddressKey:           pulumi.Any(addressActionVerificationAddressKey),
//				City:                 pulumi.Any(addressActionVerificationCity),
//				CompanyName:          pulumi.Any(addressActionVerificationCompanyName),
//				ContributorClass:     pulumi.Any(addressActionVerificationContributorClass),
//				Country:              pulumi.Any(addressActionVerificationCountry),
//				County:               pulumi.Any(addressActionVerificationCounty),
//				DepartmentName:       pulumi.Any(addressActionVerificationDepartmentName),
//				EmailAddress:         pulumi.Any(addressActionVerificationEmailAddress),
//				FirstName:            pulumi.Any(addressActionVerificationFirstName),
//				InternalNumber:       pulumi.Any(addressActionVerificationInternalNumber),
//				JobTitle:             pulumi.Any(addressActionVerificationJobTitle),
//				LastName:             pulumi.Any(addressActionVerificationLastName),
//				Line1:                pulumi.Any(addressActionVerificationLine1),
//				Line2:                pulumi.Any(addressActionVerificationLine2),
//				Line3:                pulumi.Any(addressActionVerificationLine3),
//				Line4:                pulumi.Any(addressActionVerificationLine4),
//				MiddleName:           pulumi.Any(addressActionVerificationMiddleName),
//				MunicipalInscription: pulumi.Any(addressActionVerificationMunicipalInscription),
//				PhoneCountryCode:     pulumi.Any(addressActionVerificationPhoneCountryCode),
//				PhoneNumber:          pulumi.Any(addressActionVerificationPhoneNumber),
//				PostalCode:           pulumi.Any(addressActionVerificationPostalCode),
//				Province:             pulumi.Any(addressActionVerificationProvince),
//				State:                pulumi.Any(addressActionVerificationState),
//				StateInscription:     pulumi.Any(addressActionVerificationStateInscription),
//				StreetName:           pulumi.Any(addressActionVerificationStreetName),
//				StreetNumber:         pulumi.Any(addressActionVerificationStreetNumber),
//			})
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
//
// ## Import
//
// AddressActionVerifications can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:OspGateway/addressActionVerification:AddressActionVerification test_address_action_verification "id"
// ```
type AddressActionVerification struct {
	pulumi.CustomResourceState

	// Address identifier.
	AddressKey pulumi.StringOutput `pulumi:"addressKey"`
	// Address details model.
	Addresses AddressActionVerificationAddressArrayOutput `pulumi:"addresses"`
	// Name of the city.
	City pulumi.StringOutput `pulumi:"city"`
	// Name of the customer company.
	CompanyName pulumi.StringOutput `pulumi:"companyName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// Contributor class of the customer company.
	ContributorClass pulumi.StringOutput `pulumi:"contributorClass"`
	// Country of the address.
	Country pulumi.StringOutput `pulumi:"country"`
	// County of the address.
	County pulumi.StringOutput `pulumi:"county"`
	// Department name of the customer company.
	DepartmentName pulumi.StringOutput `pulumi:"departmentName"`
	// Contact person email address.
	EmailAddress pulumi.StringOutput `pulumi:"emailAddress"`
	// First name of the contact person.
	FirstName pulumi.StringOutput `pulumi:"firstName"`
	// Internal number of the customer company.
	InternalNumber pulumi.StringOutput `pulumi:"internalNumber"`
	// Job title of the contact person.
	JobTitle pulumi.StringOutput `pulumi:"jobTitle"`
	// Last name of the contact person.
	LastName pulumi.StringOutput `pulumi:"lastName"`
	// Address line 1.
	Line1 pulumi.StringOutput `pulumi:"line1"`
	// Address line 2.
	Line2 pulumi.StringOutput `pulumi:"line2"`
	// Address line 3.
	Line3 pulumi.StringOutput `pulumi:"line3"`
	// Address line 4.
	Line4 pulumi.StringOutput `pulumi:"line4"`
	// Middle name of the contact person.
	MiddleName pulumi.StringOutput `pulumi:"middleName"`
	// Municipal Inscription.
	MunicipalInscription pulumi.StringOutput `pulumi:"municipalInscription"`
	// The home region's public name of the logged in user.
	OspHomeRegion pulumi.StringOutput `pulumi:"ospHomeRegion"`
	// Phone country code of the contact person.
	PhoneCountryCode pulumi.StringOutput `pulumi:"phoneCountryCode"`
	// Phone number of the contact person.
	PhoneNumber pulumi.StringOutput `pulumi:"phoneNumber"`
	// Post code of the address.
	PostalCode pulumi.StringOutput `pulumi:"postalCode"`
	// Province of the address.
	Province pulumi.StringOutput `pulumi:"province"`
	// Address quality type.
	Quality pulumi.StringOutput `pulumi:"quality"`
	// State of the address.
	State pulumi.StringOutput `pulumi:"state"`
	// State Inscription.
	StateInscription pulumi.StringOutput `pulumi:"stateInscription"`
	// Street name of the address.
	StreetName pulumi.StringOutput `pulumi:"streetName"`
	// Street number of the address.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	StreetNumber pulumi.StringOutput `pulumi:"streetNumber"`
	// Address verification code.
	VerificationCode pulumi.StringOutput `pulumi:"verificationCode"`
}

// NewAddressActionVerification registers a new resource with the given unique name, arguments, and options.
func NewAddressActionVerification(ctx *pulumi.Context,
	name string, args *AddressActionVerificationArgs, opts ...pulumi.ResourceOption) (*AddressActionVerification, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.OspHomeRegion == nil {
		return nil, errors.New("invalid value for required argument 'OspHomeRegion'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource AddressActionVerification
	err := ctx.RegisterResource("oci:OspGateway/addressActionVerification:AddressActionVerification", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetAddressActionVerification gets an existing AddressActionVerification resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetAddressActionVerification(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *AddressActionVerificationState, opts ...pulumi.ResourceOption) (*AddressActionVerification, error) {
	var resource AddressActionVerification
	err := ctx.ReadResource("oci:OspGateway/addressActionVerification:AddressActionVerification", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering AddressActionVerification resources.
type addressActionVerificationState struct {
	// Address identifier.
	AddressKey *string `pulumi:"addressKey"`
	// Address details model.
	Addresses []AddressActionVerificationAddress `pulumi:"addresses"`
	// Name of the city.
	City *string `pulumi:"city"`
	// Name of the customer company.
	CompanyName *string `pulumi:"companyName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// Contributor class of the customer company.
	ContributorClass *string `pulumi:"contributorClass"`
	// Country of the address.
	Country *string `pulumi:"country"`
	// County of the address.
	County *string `pulumi:"county"`
	// Department name of the customer company.
	DepartmentName *string `pulumi:"departmentName"`
	// Contact person email address.
	EmailAddress *string `pulumi:"emailAddress"`
	// First name of the contact person.
	FirstName *string `pulumi:"firstName"`
	// Internal number of the customer company.
	InternalNumber *string `pulumi:"internalNumber"`
	// Job title of the contact person.
	JobTitle *string `pulumi:"jobTitle"`
	// Last name of the contact person.
	LastName *string `pulumi:"lastName"`
	// Address line 1.
	Line1 *string `pulumi:"line1"`
	// Address line 2.
	Line2 *string `pulumi:"line2"`
	// Address line 3.
	Line3 *string `pulumi:"line3"`
	// Address line 4.
	Line4 *string `pulumi:"line4"`
	// Middle name of the contact person.
	MiddleName *string `pulumi:"middleName"`
	// Municipal Inscription.
	MunicipalInscription *string `pulumi:"municipalInscription"`
	// The home region's public name of the logged in user.
	OspHomeRegion *string `pulumi:"ospHomeRegion"`
	// Phone country code of the contact person.
	PhoneCountryCode *string `pulumi:"phoneCountryCode"`
	// Phone number of the contact person.
	PhoneNumber *string `pulumi:"phoneNumber"`
	// Post code of the address.
	PostalCode *string `pulumi:"postalCode"`
	// Province of the address.
	Province *string `pulumi:"province"`
	// Address quality type.
	Quality *string `pulumi:"quality"`
	// State of the address.
	State *string `pulumi:"state"`
	// State Inscription.
	StateInscription *string `pulumi:"stateInscription"`
	// Street name of the address.
	StreetName *string `pulumi:"streetName"`
	// Street number of the address.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	StreetNumber *string `pulumi:"streetNumber"`
	// Address verification code.
	VerificationCode *string `pulumi:"verificationCode"`
}

type AddressActionVerificationState struct {
	// Address identifier.
	AddressKey pulumi.StringPtrInput
	// Address details model.
	Addresses AddressActionVerificationAddressArrayInput
	// Name of the city.
	City pulumi.StringPtrInput
	// Name of the customer company.
	CompanyName pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringPtrInput
	// Contributor class of the customer company.
	ContributorClass pulumi.StringPtrInput
	// Country of the address.
	Country pulumi.StringPtrInput
	// County of the address.
	County pulumi.StringPtrInput
	// Department name of the customer company.
	DepartmentName pulumi.StringPtrInput
	// Contact person email address.
	EmailAddress pulumi.StringPtrInput
	// First name of the contact person.
	FirstName pulumi.StringPtrInput
	// Internal number of the customer company.
	InternalNumber pulumi.StringPtrInput
	// Job title of the contact person.
	JobTitle pulumi.StringPtrInput
	// Last name of the contact person.
	LastName pulumi.StringPtrInput
	// Address line 1.
	Line1 pulumi.StringPtrInput
	// Address line 2.
	Line2 pulumi.StringPtrInput
	// Address line 3.
	Line3 pulumi.StringPtrInput
	// Address line 4.
	Line4 pulumi.StringPtrInput
	// Middle name of the contact person.
	MiddleName pulumi.StringPtrInput
	// Municipal Inscription.
	MunicipalInscription pulumi.StringPtrInput
	// The home region's public name of the logged in user.
	OspHomeRegion pulumi.StringPtrInput
	// Phone country code of the contact person.
	PhoneCountryCode pulumi.StringPtrInput
	// Phone number of the contact person.
	PhoneNumber pulumi.StringPtrInput
	// Post code of the address.
	PostalCode pulumi.StringPtrInput
	// Province of the address.
	Province pulumi.StringPtrInput
	// Address quality type.
	Quality pulumi.StringPtrInput
	// State of the address.
	State pulumi.StringPtrInput
	// State Inscription.
	StateInscription pulumi.StringPtrInput
	// Street name of the address.
	StreetName pulumi.StringPtrInput
	// Street number of the address.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	StreetNumber pulumi.StringPtrInput
	// Address verification code.
	VerificationCode pulumi.StringPtrInput
}

func (AddressActionVerificationState) ElementType() reflect.Type {
	return reflect.TypeOf((*addressActionVerificationState)(nil)).Elem()
}

type addressActionVerificationArgs struct {
	// Address identifier.
	AddressKey *string `pulumi:"addressKey"`
	// Name of the city.
	City *string `pulumi:"city"`
	// Name of the customer company.
	CompanyName *string `pulumi:"companyName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// Contributor class of the customer company.
	ContributorClass *string `pulumi:"contributorClass"`
	// Country of the address.
	Country *string `pulumi:"country"`
	// County of the address.
	County *string `pulumi:"county"`
	// Department name of the customer company.
	DepartmentName *string `pulumi:"departmentName"`
	// Contact person email address.
	EmailAddress *string `pulumi:"emailAddress"`
	// First name of the contact person.
	FirstName *string `pulumi:"firstName"`
	// Internal number of the customer company.
	InternalNumber *string `pulumi:"internalNumber"`
	// Job title of the contact person.
	JobTitle *string `pulumi:"jobTitle"`
	// Last name of the contact person.
	LastName *string `pulumi:"lastName"`
	// Address line 1.
	Line1 *string `pulumi:"line1"`
	// Address line 2.
	Line2 *string `pulumi:"line2"`
	// Address line 3.
	Line3 *string `pulumi:"line3"`
	// Address line 4.
	Line4 *string `pulumi:"line4"`
	// Middle name of the contact person.
	MiddleName *string `pulumi:"middleName"`
	// Municipal Inscription.
	MunicipalInscription *string `pulumi:"municipalInscription"`
	// The home region's public name of the logged in user.
	OspHomeRegion string `pulumi:"ospHomeRegion"`
	// Phone country code of the contact person.
	PhoneCountryCode *string `pulumi:"phoneCountryCode"`
	// Phone number of the contact person.
	PhoneNumber *string `pulumi:"phoneNumber"`
	// Post code of the address.
	PostalCode *string `pulumi:"postalCode"`
	// Province of the address.
	Province *string `pulumi:"province"`
	// State of the address.
	State *string `pulumi:"state"`
	// State Inscription.
	StateInscription *string `pulumi:"stateInscription"`
	// Street name of the address.
	StreetName *string `pulumi:"streetName"`
	// Street number of the address.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	StreetNumber *string `pulumi:"streetNumber"`
}

// The set of arguments for constructing a AddressActionVerification resource.
type AddressActionVerificationArgs struct {
	// Address identifier.
	AddressKey pulumi.StringPtrInput
	// Name of the city.
	City pulumi.StringPtrInput
	// Name of the customer company.
	CompanyName pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput
	// Contributor class of the customer company.
	ContributorClass pulumi.StringPtrInput
	// Country of the address.
	Country pulumi.StringPtrInput
	// County of the address.
	County pulumi.StringPtrInput
	// Department name of the customer company.
	DepartmentName pulumi.StringPtrInput
	// Contact person email address.
	EmailAddress pulumi.StringPtrInput
	// First name of the contact person.
	FirstName pulumi.StringPtrInput
	// Internal number of the customer company.
	InternalNumber pulumi.StringPtrInput
	// Job title of the contact person.
	JobTitle pulumi.StringPtrInput
	// Last name of the contact person.
	LastName pulumi.StringPtrInput
	// Address line 1.
	Line1 pulumi.StringPtrInput
	// Address line 2.
	Line2 pulumi.StringPtrInput
	// Address line 3.
	Line3 pulumi.StringPtrInput
	// Address line 4.
	Line4 pulumi.StringPtrInput
	// Middle name of the contact person.
	MiddleName pulumi.StringPtrInput
	// Municipal Inscription.
	MunicipalInscription pulumi.StringPtrInput
	// The home region's public name of the logged in user.
	OspHomeRegion pulumi.StringInput
	// Phone country code of the contact person.
	PhoneCountryCode pulumi.StringPtrInput
	// Phone number of the contact person.
	PhoneNumber pulumi.StringPtrInput
	// Post code of the address.
	PostalCode pulumi.StringPtrInput
	// Province of the address.
	Province pulumi.StringPtrInput
	// State of the address.
	State pulumi.StringPtrInput
	// State Inscription.
	StateInscription pulumi.StringPtrInput
	// Street name of the address.
	StreetName pulumi.StringPtrInput
	// Street number of the address.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	StreetNumber pulumi.StringPtrInput
}

func (AddressActionVerificationArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*addressActionVerificationArgs)(nil)).Elem()
}

type AddressActionVerificationInput interface {
	pulumi.Input

	ToAddressActionVerificationOutput() AddressActionVerificationOutput
	ToAddressActionVerificationOutputWithContext(ctx context.Context) AddressActionVerificationOutput
}

func (*AddressActionVerification) ElementType() reflect.Type {
	return reflect.TypeOf((**AddressActionVerification)(nil)).Elem()
}

func (i *AddressActionVerification) ToAddressActionVerificationOutput() AddressActionVerificationOutput {
	return i.ToAddressActionVerificationOutputWithContext(context.Background())
}

func (i *AddressActionVerification) ToAddressActionVerificationOutputWithContext(ctx context.Context) AddressActionVerificationOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AddressActionVerificationOutput)
}

// AddressActionVerificationArrayInput is an input type that accepts AddressActionVerificationArray and AddressActionVerificationArrayOutput values.
// You can construct a concrete instance of `AddressActionVerificationArrayInput` via:
//
//	AddressActionVerificationArray{ AddressActionVerificationArgs{...} }
type AddressActionVerificationArrayInput interface {
	pulumi.Input

	ToAddressActionVerificationArrayOutput() AddressActionVerificationArrayOutput
	ToAddressActionVerificationArrayOutputWithContext(context.Context) AddressActionVerificationArrayOutput
}

type AddressActionVerificationArray []AddressActionVerificationInput

func (AddressActionVerificationArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*AddressActionVerification)(nil)).Elem()
}

func (i AddressActionVerificationArray) ToAddressActionVerificationArrayOutput() AddressActionVerificationArrayOutput {
	return i.ToAddressActionVerificationArrayOutputWithContext(context.Background())
}

func (i AddressActionVerificationArray) ToAddressActionVerificationArrayOutputWithContext(ctx context.Context) AddressActionVerificationArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AddressActionVerificationArrayOutput)
}

// AddressActionVerificationMapInput is an input type that accepts AddressActionVerificationMap and AddressActionVerificationMapOutput values.
// You can construct a concrete instance of `AddressActionVerificationMapInput` via:
//
//	AddressActionVerificationMap{ "key": AddressActionVerificationArgs{...} }
type AddressActionVerificationMapInput interface {
	pulumi.Input

	ToAddressActionVerificationMapOutput() AddressActionVerificationMapOutput
	ToAddressActionVerificationMapOutputWithContext(context.Context) AddressActionVerificationMapOutput
}

type AddressActionVerificationMap map[string]AddressActionVerificationInput

func (AddressActionVerificationMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*AddressActionVerification)(nil)).Elem()
}

func (i AddressActionVerificationMap) ToAddressActionVerificationMapOutput() AddressActionVerificationMapOutput {
	return i.ToAddressActionVerificationMapOutputWithContext(context.Background())
}

func (i AddressActionVerificationMap) ToAddressActionVerificationMapOutputWithContext(ctx context.Context) AddressActionVerificationMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AddressActionVerificationMapOutput)
}

type AddressActionVerificationOutput struct{ *pulumi.OutputState }

func (AddressActionVerificationOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**AddressActionVerification)(nil)).Elem()
}

func (o AddressActionVerificationOutput) ToAddressActionVerificationOutput() AddressActionVerificationOutput {
	return o
}

func (o AddressActionVerificationOutput) ToAddressActionVerificationOutputWithContext(ctx context.Context) AddressActionVerificationOutput {
	return o
}

// Address identifier.
func (o AddressActionVerificationOutput) AddressKey() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.AddressKey }).(pulumi.StringOutput)
}

// Address details model.
func (o AddressActionVerificationOutput) Addresses() AddressActionVerificationAddressArrayOutput {
	return o.ApplyT(func(v *AddressActionVerification) AddressActionVerificationAddressArrayOutput { return v.Addresses }).(AddressActionVerificationAddressArrayOutput)
}

// Name of the city.
func (o AddressActionVerificationOutput) City() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.City }).(pulumi.StringOutput)
}

// Name of the customer company.
func (o AddressActionVerificationOutput) CompanyName() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.CompanyName }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o AddressActionVerificationOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// Contributor class of the customer company.
func (o AddressActionVerificationOutput) ContributorClass() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.ContributorClass }).(pulumi.StringOutput)
}

// Country of the address.
func (o AddressActionVerificationOutput) Country() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.Country }).(pulumi.StringOutput)
}

// County of the address.
func (o AddressActionVerificationOutput) County() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.County }).(pulumi.StringOutput)
}

// Department name of the customer company.
func (o AddressActionVerificationOutput) DepartmentName() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.DepartmentName }).(pulumi.StringOutput)
}

// Contact person email address.
func (o AddressActionVerificationOutput) EmailAddress() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.EmailAddress }).(pulumi.StringOutput)
}

// First name of the contact person.
func (o AddressActionVerificationOutput) FirstName() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.FirstName }).(pulumi.StringOutput)
}

// Internal number of the customer company.
func (o AddressActionVerificationOutput) InternalNumber() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.InternalNumber }).(pulumi.StringOutput)
}

// Job title of the contact person.
func (o AddressActionVerificationOutput) JobTitle() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.JobTitle }).(pulumi.StringOutput)
}

// Last name of the contact person.
func (o AddressActionVerificationOutput) LastName() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.LastName }).(pulumi.StringOutput)
}

// Address line 1.
func (o AddressActionVerificationOutput) Line1() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.Line1 }).(pulumi.StringOutput)
}

// Address line 2.
func (o AddressActionVerificationOutput) Line2() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.Line2 }).(pulumi.StringOutput)
}

// Address line 3.
func (o AddressActionVerificationOutput) Line3() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.Line3 }).(pulumi.StringOutput)
}

// Address line 4.
func (o AddressActionVerificationOutput) Line4() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.Line4 }).(pulumi.StringOutput)
}

// Middle name of the contact person.
func (o AddressActionVerificationOutput) MiddleName() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.MiddleName }).(pulumi.StringOutput)
}

// Municipal Inscription.
func (o AddressActionVerificationOutput) MunicipalInscription() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.MunicipalInscription }).(pulumi.StringOutput)
}

// The home region's public name of the logged in user.
func (o AddressActionVerificationOutput) OspHomeRegion() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.OspHomeRegion }).(pulumi.StringOutput)
}

// Phone country code of the contact person.
func (o AddressActionVerificationOutput) PhoneCountryCode() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.PhoneCountryCode }).(pulumi.StringOutput)
}

// Phone number of the contact person.
func (o AddressActionVerificationOutput) PhoneNumber() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.PhoneNumber }).(pulumi.StringOutput)
}

// Post code of the address.
func (o AddressActionVerificationOutput) PostalCode() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.PostalCode }).(pulumi.StringOutput)
}

// Province of the address.
func (o AddressActionVerificationOutput) Province() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.Province }).(pulumi.StringOutput)
}

// Address quality type.
func (o AddressActionVerificationOutput) Quality() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.Quality }).(pulumi.StringOutput)
}

// State of the address.
func (o AddressActionVerificationOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// State Inscription.
func (o AddressActionVerificationOutput) StateInscription() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.StateInscription }).(pulumi.StringOutput)
}

// Street name of the address.
func (o AddressActionVerificationOutput) StreetName() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.StreetName }).(pulumi.StringOutput)
}

// Street number of the address.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o AddressActionVerificationOutput) StreetNumber() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.StreetNumber }).(pulumi.StringOutput)
}

// Address verification code.
func (o AddressActionVerificationOutput) VerificationCode() pulumi.StringOutput {
	return o.ApplyT(func(v *AddressActionVerification) pulumi.StringOutput { return v.VerificationCode }).(pulumi.StringOutput)
}

type AddressActionVerificationArrayOutput struct{ *pulumi.OutputState }

func (AddressActionVerificationArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*AddressActionVerification)(nil)).Elem()
}

func (o AddressActionVerificationArrayOutput) ToAddressActionVerificationArrayOutput() AddressActionVerificationArrayOutput {
	return o
}

func (o AddressActionVerificationArrayOutput) ToAddressActionVerificationArrayOutputWithContext(ctx context.Context) AddressActionVerificationArrayOutput {
	return o
}

func (o AddressActionVerificationArrayOutput) Index(i pulumi.IntInput) AddressActionVerificationOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *AddressActionVerification {
		return vs[0].([]*AddressActionVerification)[vs[1].(int)]
	}).(AddressActionVerificationOutput)
}

type AddressActionVerificationMapOutput struct{ *pulumi.OutputState }

func (AddressActionVerificationMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*AddressActionVerification)(nil)).Elem()
}

func (o AddressActionVerificationMapOutput) ToAddressActionVerificationMapOutput() AddressActionVerificationMapOutput {
	return o
}

func (o AddressActionVerificationMapOutput) ToAddressActionVerificationMapOutputWithContext(ctx context.Context) AddressActionVerificationMapOutput {
	return o
}

func (o AddressActionVerificationMapOutput) MapIndex(k pulumi.StringInput) AddressActionVerificationOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *AddressActionVerification {
		return vs[0].(map[string]*AddressActionVerification)[vs[1].(string)]
	}).(AddressActionVerificationOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*AddressActionVerificationInput)(nil)).Elem(), &AddressActionVerification{})
	pulumi.RegisterInputType(reflect.TypeOf((*AddressActionVerificationArrayInput)(nil)).Elem(), AddressActionVerificationArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*AddressActionVerificationMapInput)(nil)).Elem(), AddressActionVerificationMap{})
	pulumi.RegisterOutputType(AddressActionVerificationOutput{})
	pulumi.RegisterOutputType(AddressActionVerificationArrayOutput{})
	pulumi.RegisterOutputType(AddressActionVerificationMapOutput{})
}
