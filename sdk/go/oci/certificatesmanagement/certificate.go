// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package certificatesmanagement

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Certificate resource in Oracle Cloud Infrastructure Certificates Management service.
//
// Creates a new certificate according to the details of the request.
//
// ## Import
//
// Certificates can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:CertificatesManagement/certificate:Certificate test_certificate "id"
//
// ```
type Certificate struct {
	pulumi.CustomResourceState

	// (Updatable) The details of the contents of the certificate and certificate metadata.
	CertificateConfig CertificateCertificateConfigOutput `pulumi:"certificateConfig"`
	// The name of the profile used to create the certificate, which depends on the type of certificate you need.
	CertificateProfileType pulumi.StringOutput `pulumi:"certificateProfileType"`
	// The details of the certificate revocation list (CRL).
	CertificateRevocationListDetails CertificateCertificateRevocationListDetailArrayOutput `pulumi:"certificateRevocationListDetails"`
	// (Updatable) An optional list of rules that control how the certificate is used and managed.
	CertificateRules CertificateCertificateRuleArrayOutput `pulumi:"certificateRules"`
	// (Updatable) The OCID of the compartment where you want to create the certificate.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) The origin of the certificate.
	ConfigType pulumi.StringOutput `pulumi:"configType"`
	// The details of the certificate version. This object does not contain the certificate contents.
	CurrentVersions CertificateCurrentVersionArrayOutput `pulumi:"currentVersions"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) A brief description of the certificate. Avoid entering confidential information.
	Description pulumi.StringPtrOutput `pulumi:"description"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// The OCID of the private CA.
	IssuerCertificateAuthorityId pulumi.StringOutput `pulumi:"issuerCertificateAuthorityId"`
	// The algorithm to use to create key pairs.
	KeyAlgorithm pulumi.StringOutput `pulumi:"keyAlgorithm"`
	// Additional information about the current lifecycle state of the certificate.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// A user-friendly name for the certificate. Names are unique within a compartment. Avoid entering confidential information. Valid characters are uppercase or lowercase letters, numbers, hyphens, underscores, and periods.
	Name pulumi.StringOutput `pulumi:"name"`
	// The algorithm to use to sign the public key certificate.
	SignatureAlgorithm pulumi.StringOutput `pulumi:"signatureAlgorithm"`
	// The current lifecycle state of the certificate.
	State pulumi.StringOutput `pulumi:"state"`
	// The subject of the certificate, which is a distinguished name that identifies the entity that owns the public key in the certificate.
	Subjects CertificateSubjectArrayOutput `pulumi:"subjects"`
	// A property indicating when the certificate was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// An optional property indicating when to delete the certificate version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	TimeOfDeletion pulumi.StringOutput `pulumi:"timeOfDeletion"`
}

// NewCertificate registers a new resource with the given unique name, arguments, and options.
func NewCertificate(ctx *pulumi.Context,
	name string, args *CertificateArgs, opts ...pulumi.ResourceOption) (*Certificate, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CertificateConfig == nil {
		return nil, errors.New("invalid value for required argument 'CertificateConfig'")
	}
	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	var resource Certificate
	err := ctx.RegisterResource("oci:CertificatesManagement/certificate:Certificate", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetCertificate gets an existing Certificate resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetCertificate(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *CertificateState, opts ...pulumi.ResourceOption) (*Certificate, error) {
	var resource Certificate
	err := ctx.ReadResource("oci:CertificatesManagement/certificate:Certificate", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Certificate resources.
type certificateState struct {
	// (Updatable) The details of the contents of the certificate and certificate metadata.
	CertificateConfig *CertificateCertificateConfig `pulumi:"certificateConfig"`
	// The name of the profile used to create the certificate, which depends on the type of certificate you need.
	CertificateProfileType *string `pulumi:"certificateProfileType"`
	// The details of the certificate revocation list (CRL).
	CertificateRevocationListDetails []CertificateCertificateRevocationListDetail `pulumi:"certificateRevocationListDetails"`
	// (Updatable) An optional list of rules that control how the certificate is used and managed.
	CertificateRules []CertificateCertificateRule `pulumi:"certificateRules"`
	// (Updatable) The OCID of the compartment where you want to create the certificate.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) The origin of the certificate.
	ConfigType *string `pulumi:"configType"`
	// The details of the certificate version. This object does not contain the certificate contents.
	CurrentVersions []CertificateCurrentVersion `pulumi:"currentVersions"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A brief description of the certificate. Avoid entering confidential information.
	Description *string `pulumi:"description"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The OCID of the private CA.
	IssuerCertificateAuthorityId *string `pulumi:"issuerCertificateAuthorityId"`
	// The algorithm to use to create key pairs.
	KeyAlgorithm *string `pulumi:"keyAlgorithm"`
	// Additional information about the current lifecycle state of the certificate.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// A user-friendly name for the certificate. Names are unique within a compartment. Avoid entering confidential information. Valid characters are uppercase or lowercase letters, numbers, hyphens, underscores, and periods.
	Name *string `pulumi:"name"`
	// The algorithm to use to sign the public key certificate.
	SignatureAlgorithm *string `pulumi:"signatureAlgorithm"`
	// The current lifecycle state of the certificate.
	State *string `pulumi:"state"`
	// The subject of the certificate, which is a distinguished name that identifies the entity that owns the public key in the certificate.
	Subjects []CertificateSubject `pulumi:"subjects"`
	// A property indicating when the certificate was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
	// An optional property indicating when to delete the certificate version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	TimeOfDeletion *string `pulumi:"timeOfDeletion"`
}

type CertificateState struct {
	// (Updatable) The details of the contents of the certificate and certificate metadata.
	CertificateConfig CertificateCertificateConfigPtrInput
	// The name of the profile used to create the certificate, which depends on the type of certificate you need.
	CertificateProfileType pulumi.StringPtrInput
	// The details of the certificate revocation list (CRL).
	CertificateRevocationListDetails CertificateCertificateRevocationListDetailArrayInput
	// (Updatable) An optional list of rules that control how the certificate is used and managed.
	CertificateRules CertificateCertificateRuleArrayInput
	// (Updatable) The OCID of the compartment where you want to create the certificate.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) The origin of the certificate.
	ConfigType pulumi.StringPtrInput
	// The details of the certificate version. This object does not contain the certificate contents.
	CurrentVersions CertificateCurrentVersionArrayInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A brief description of the certificate. Avoid entering confidential information.
	Description pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The OCID of the private CA.
	IssuerCertificateAuthorityId pulumi.StringPtrInput
	// The algorithm to use to create key pairs.
	KeyAlgorithm pulumi.StringPtrInput
	// Additional information about the current lifecycle state of the certificate.
	LifecycleDetails pulumi.StringPtrInput
	// A user-friendly name for the certificate. Names are unique within a compartment. Avoid entering confidential information. Valid characters are uppercase or lowercase letters, numbers, hyphens, underscores, and periods.
	Name pulumi.StringPtrInput
	// The algorithm to use to sign the public key certificate.
	SignatureAlgorithm pulumi.StringPtrInput
	// The current lifecycle state of the certificate.
	State pulumi.StringPtrInput
	// The subject of the certificate, which is a distinguished name that identifies the entity that owns the public key in the certificate.
	Subjects CertificateSubjectArrayInput
	// A property indicating when the certificate was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
	// An optional property indicating when to delete the certificate version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	TimeOfDeletion pulumi.StringPtrInput
}

func (CertificateState) ElementType() reflect.Type {
	return reflect.TypeOf((*certificateState)(nil)).Elem()
}

type certificateArgs struct {
	// (Updatable) The details of the contents of the certificate and certificate metadata.
	CertificateConfig CertificateCertificateConfig `pulumi:"certificateConfig"`
	// (Updatable) An optional list of rules that control how the certificate is used and managed.
	CertificateRules []CertificateCertificateRule `pulumi:"certificateRules"`
	// (Updatable) The OCID of the compartment where you want to create the certificate.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A brief description of the certificate. Avoid entering confidential information.
	Description *string `pulumi:"description"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// A user-friendly name for the certificate. Names are unique within a compartment. Avoid entering confidential information. Valid characters are uppercase or lowercase letters, numbers, hyphens, underscores, and periods.
	Name *string `pulumi:"name"`
}

// The set of arguments for constructing a Certificate resource.
type CertificateArgs struct {
	// (Updatable) The details of the contents of the certificate and certificate metadata.
	CertificateConfig CertificateCertificateConfigInput
	// (Updatable) An optional list of rules that control how the certificate is used and managed.
	CertificateRules CertificateCertificateRuleArrayInput
	// (Updatable) The OCID of the compartment where you want to create the certificate.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A brief description of the certificate. Avoid entering confidential information.
	Description pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// A user-friendly name for the certificate. Names are unique within a compartment. Avoid entering confidential information. Valid characters are uppercase or lowercase letters, numbers, hyphens, underscores, and periods.
	Name pulumi.StringPtrInput
}

func (CertificateArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*certificateArgs)(nil)).Elem()
}

type CertificateInput interface {
	pulumi.Input

	ToCertificateOutput() CertificateOutput
	ToCertificateOutputWithContext(ctx context.Context) CertificateOutput
}

func (*Certificate) ElementType() reflect.Type {
	return reflect.TypeOf((**Certificate)(nil)).Elem()
}

func (i *Certificate) ToCertificateOutput() CertificateOutput {
	return i.ToCertificateOutputWithContext(context.Background())
}

func (i *Certificate) ToCertificateOutputWithContext(ctx context.Context) CertificateOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CertificateOutput)
}

// CertificateArrayInput is an input type that accepts CertificateArray and CertificateArrayOutput values.
// You can construct a concrete instance of `CertificateArrayInput` via:
//
//	CertificateArray{ CertificateArgs{...} }
type CertificateArrayInput interface {
	pulumi.Input

	ToCertificateArrayOutput() CertificateArrayOutput
	ToCertificateArrayOutputWithContext(context.Context) CertificateArrayOutput
}

type CertificateArray []CertificateInput

func (CertificateArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Certificate)(nil)).Elem()
}

func (i CertificateArray) ToCertificateArrayOutput() CertificateArrayOutput {
	return i.ToCertificateArrayOutputWithContext(context.Background())
}

func (i CertificateArray) ToCertificateArrayOutputWithContext(ctx context.Context) CertificateArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CertificateArrayOutput)
}

// CertificateMapInput is an input type that accepts CertificateMap and CertificateMapOutput values.
// You can construct a concrete instance of `CertificateMapInput` via:
//
//	CertificateMap{ "key": CertificateArgs{...} }
type CertificateMapInput interface {
	pulumi.Input

	ToCertificateMapOutput() CertificateMapOutput
	ToCertificateMapOutputWithContext(context.Context) CertificateMapOutput
}

type CertificateMap map[string]CertificateInput

func (CertificateMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Certificate)(nil)).Elem()
}

func (i CertificateMap) ToCertificateMapOutput() CertificateMapOutput {
	return i.ToCertificateMapOutputWithContext(context.Background())
}

func (i CertificateMap) ToCertificateMapOutputWithContext(ctx context.Context) CertificateMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CertificateMapOutput)
}

type CertificateOutput struct{ *pulumi.OutputState }

func (CertificateOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Certificate)(nil)).Elem()
}

func (o CertificateOutput) ToCertificateOutput() CertificateOutput {
	return o
}

func (o CertificateOutput) ToCertificateOutputWithContext(ctx context.Context) CertificateOutput {
	return o
}

// (Updatable) The details of the contents of the certificate and certificate metadata.
func (o CertificateOutput) CertificateConfig() CertificateCertificateConfigOutput {
	return o.ApplyT(func(v *Certificate) CertificateCertificateConfigOutput { return v.CertificateConfig }).(CertificateCertificateConfigOutput)
}

// The name of the profile used to create the certificate, which depends on the type of certificate you need.
func (o CertificateOutput) CertificateProfileType() pulumi.StringOutput {
	return o.ApplyT(func(v *Certificate) pulumi.StringOutput { return v.CertificateProfileType }).(pulumi.StringOutput)
}

// The details of the certificate revocation list (CRL).
func (o CertificateOutput) CertificateRevocationListDetails() CertificateCertificateRevocationListDetailArrayOutput {
	return o.ApplyT(func(v *Certificate) CertificateCertificateRevocationListDetailArrayOutput {
		return v.CertificateRevocationListDetails
	}).(CertificateCertificateRevocationListDetailArrayOutput)
}

// (Updatable) An optional list of rules that control how the certificate is used and managed.
func (o CertificateOutput) CertificateRules() CertificateCertificateRuleArrayOutput {
	return o.ApplyT(func(v *Certificate) CertificateCertificateRuleArrayOutput { return v.CertificateRules }).(CertificateCertificateRuleArrayOutput)
}

// (Updatable) The OCID of the compartment where you want to create the certificate.
func (o CertificateOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *Certificate) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) The origin of the certificate.
func (o CertificateOutput) ConfigType() pulumi.StringOutput {
	return o.ApplyT(func(v *Certificate) pulumi.StringOutput { return v.ConfigType }).(pulumi.StringOutput)
}

// The details of the certificate version. This object does not contain the certificate contents.
func (o CertificateOutput) CurrentVersions() CertificateCurrentVersionArrayOutput {
	return o.ApplyT(func(v *Certificate) CertificateCurrentVersionArrayOutput { return v.CurrentVersions }).(CertificateCurrentVersionArrayOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o CertificateOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *Certificate) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
}

// (Updatable) A brief description of the certificate. Avoid entering confidential information.
func (o CertificateOutput) Description() pulumi.StringPtrOutput {
	return o.ApplyT(func(v *Certificate) pulumi.StringPtrOutput { return v.Description }).(pulumi.StringPtrOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
func (o CertificateOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *Certificate) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// The OCID of the private CA.
func (o CertificateOutput) IssuerCertificateAuthorityId() pulumi.StringOutput {
	return o.ApplyT(func(v *Certificate) pulumi.StringOutput { return v.IssuerCertificateAuthorityId }).(pulumi.StringOutput)
}

// The algorithm to use to create key pairs.
func (o CertificateOutput) KeyAlgorithm() pulumi.StringOutput {
	return o.ApplyT(func(v *Certificate) pulumi.StringOutput { return v.KeyAlgorithm }).(pulumi.StringOutput)
}

// Additional information about the current lifecycle state of the certificate.
func (o CertificateOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *Certificate) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// A user-friendly name for the certificate. Names are unique within a compartment. Avoid entering confidential information. Valid characters are uppercase or lowercase letters, numbers, hyphens, underscores, and periods.
func (o CertificateOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v *Certificate) pulumi.StringOutput { return v.Name }).(pulumi.StringOutput)
}

// The algorithm to use to sign the public key certificate.
func (o CertificateOutput) SignatureAlgorithm() pulumi.StringOutput {
	return o.ApplyT(func(v *Certificate) pulumi.StringOutput { return v.SignatureAlgorithm }).(pulumi.StringOutput)
}

// The current lifecycle state of the certificate.
func (o CertificateOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *Certificate) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The subject of the certificate, which is a distinguished name that identifies the entity that owns the public key in the certificate.
func (o CertificateOutput) Subjects() CertificateSubjectArrayOutput {
	return o.ApplyT(func(v *Certificate) CertificateSubjectArrayOutput { return v.Subjects }).(CertificateSubjectArrayOutput)
}

// A property indicating when the certificate was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
func (o CertificateOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *Certificate) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// An optional property indicating when to delete the certificate version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
func (o CertificateOutput) TimeOfDeletion() pulumi.StringOutput {
	return o.ApplyT(func(v *Certificate) pulumi.StringOutput { return v.TimeOfDeletion }).(pulumi.StringOutput)
}

type CertificateArrayOutput struct{ *pulumi.OutputState }

func (CertificateArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Certificate)(nil)).Elem()
}

func (o CertificateArrayOutput) ToCertificateArrayOutput() CertificateArrayOutput {
	return o
}

func (o CertificateArrayOutput) ToCertificateArrayOutputWithContext(ctx context.Context) CertificateArrayOutput {
	return o
}

func (o CertificateArrayOutput) Index(i pulumi.IntInput) CertificateOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Certificate {
		return vs[0].([]*Certificate)[vs[1].(int)]
	}).(CertificateOutput)
}

type CertificateMapOutput struct{ *pulumi.OutputState }

func (CertificateMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Certificate)(nil)).Elem()
}

func (o CertificateMapOutput) ToCertificateMapOutput() CertificateMapOutput {
	return o
}

func (o CertificateMapOutput) ToCertificateMapOutputWithContext(ctx context.Context) CertificateMapOutput {
	return o
}

func (o CertificateMapOutput) MapIndex(k pulumi.StringInput) CertificateOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Certificate {
		return vs[0].(map[string]*Certificate)[vs[1].(string)]
	}).(CertificateOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*CertificateInput)(nil)).Elem(), &Certificate{})
	pulumi.RegisterInputType(reflect.TypeOf((*CertificateArrayInput)(nil)).Elem(), CertificateArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*CertificateMapInput)(nil)).Elem(), CertificateMap{})
	pulumi.RegisterOutputType(CertificateOutput{})
	pulumi.RegisterOutputType(CertificateArrayOutput{})
	pulumi.RegisterOutputType(CertificateMapOutput{})
}