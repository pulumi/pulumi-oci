// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package email

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Sender resource in Oracle Cloud Infrastructure Email service.
//
// Creates a sender for a tenancy in a given compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Email"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Email.NewSender(ctx, "testSender", &Email.SenderArgs{
//				CompartmentId: pulumi.Any(_var.Compartment_id),
//				EmailAddress:  pulumi.Any(_var.Sender_email_address),
//				DefinedTags: pulumi.AnyMap{
//					"Operations.CostCenter": pulumi.Any("42"),
//				},
//				FreeformTags: pulumi.AnyMap{
//					"Department": pulumi.Any("Finance"),
//				},
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
// Senders can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:Email/sender:Sender test_sender "id"
//
// ```
type Sender struct {
	pulumi.CustomResourceState

	// (Updatable) The OCID of the compartment that contains the sender.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// The email address of the sender.
	EmailAddress pulumi.StringOutput `pulumi:"emailAddress"`
	// The email domain used to assert responsibility for emails sent from this sender.
	EmailDomainId pulumi.StringOutput `pulumi:"emailDomainId"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// Value of the SPF field. For more information about SPF, please see [SPF Authentication](https://docs.cloud.oracle.com/iaas/Content/Email/Concepts/overview.htm#components).
	IsSpf pulumi.BoolOutput `pulumi:"isSpf"`
	// The current status of the approved sender.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the approved sender was added in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
}

// NewSender registers a new resource with the given unique name, arguments, and options.
func NewSender(ctx *pulumi.Context,
	name string, args *SenderArgs, opts ...pulumi.ResourceOption) (*Sender, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.EmailAddress == nil {
		return nil, errors.New("invalid value for required argument 'EmailAddress'")
	}
	var resource Sender
	err := ctx.RegisterResource("oci:Email/sender:Sender", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetSender gets an existing Sender resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetSender(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *SenderState, opts ...pulumi.ResourceOption) (*Sender, error) {
	var resource Sender
	err := ctx.ReadResource("oci:Email/sender:Sender", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Sender resources.
type senderState struct {
	// (Updatable) The OCID of the compartment that contains the sender.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// The email address of the sender.
	EmailAddress *string `pulumi:"emailAddress"`
	// The email domain used to assert responsibility for emails sent from this sender.
	EmailDomainId *string `pulumi:"emailDomainId"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Value of the SPF field. For more information about SPF, please see [SPF Authentication](https://docs.cloud.oracle.com/iaas/Content/Email/Concepts/overview.htm#components).
	IsSpf *bool `pulumi:"isSpf"`
	// The current status of the approved sender.
	State *string `pulumi:"state"`
	// The date and time the approved sender was added in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
	TimeCreated *string `pulumi:"timeCreated"`
}

type SenderState struct {
	// (Updatable) The OCID of the compartment that contains the sender.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// The email address of the sender.
	EmailAddress pulumi.StringPtrInput
	// The email domain used to assert responsibility for emails sent from this sender.
	EmailDomainId pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// Value of the SPF field. For more information about SPF, please see [SPF Authentication](https://docs.cloud.oracle.com/iaas/Content/Email/Concepts/overview.htm#components).
	IsSpf pulumi.BoolPtrInput
	// The current status of the approved sender.
	State pulumi.StringPtrInput
	// The date and time the approved sender was added in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
	TimeCreated pulumi.StringPtrInput
}

func (SenderState) ElementType() reflect.Type {
	return reflect.TypeOf((*senderState)(nil)).Elem()
}

type senderArgs struct {
	// (Updatable) The OCID of the compartment that contains the sender.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// The email address of the sender.
	EmailAddress string `pulumi:"emailAddress"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
}

// The set of arguments for constructing a Sender resource.
type SenderArgs struct {
	// (Updatable) The OCID of the compartment that contains the sender.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// The email address of the sender.
	EmailAddress pulumi.StringInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
}

func (SenderArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*senderArgs)(nil)).Elem()
}

type SenderInput interface {
	pulumi.Input

	ToSenderOutput() SenderOutput
	ToSenderOutputWithContext(ctx context.Context) SenderOutput
}

func (*Sender) ElementType() reflect.Type {
	return reflect.TypeOf((**Sender)(nil)).Elem()
}

func (i *Sender) ToSenderOutput() SenderOutput {
	return i.ToSenderOutputWithContext(context.Background())
}

func (i *Sender) ToSenderOutputWithContext(ctx context.Context) SenderOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SenderOutput)
}

// SenderArrayInput is an input type that accepts SenderArray and SenderArrayOutput values.
// You can construct a concrete instance of `SenderArrayInput` via:
//
//	SenderArray{ SenderArgs{...} }
type SenderArrayInput interface {
	pulumi.Input

	ToSenderArrayOutput() SenderArrayOutput
	ToSenderArrayOutputWithContext(context.Context) SenderArrayOutput
}

type SenderArray []SenderInput

func (SenderArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Sender)(nil)).Elem()
}

func (i SenderArray) ToSenderArrayOutput() SenderArrayOutput {
	return i.ToSenderArrayOutputWithContext(context.Background())
}

func (i SenderArray) ToSenderArrayOutputWithContext(ctx context.Context) SenderArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SenderArrayOutput)
}

// SenderMapInput is an input type that accepts SenderMap and SenderMapOutput values.
// You can construct a concrete instance of `SenderMapInput` via:
//
//	SenderMap{ "key": SenderArgs{...} }
type SenderMapInput interface {
	pulumi.Input

	ToSenderMapOutput() SenderMapOutput
	ToSenderMapOutputWithContext(context.Context) SenderMapOutput
}

type SenderMap map[string]SenderInput

func (SenderMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Sender)(nil)).Elem()
}

func (i SenderMap) ToSenderMapOutput() SenderMapOutput {
	return i.ToSenderMapOutputWithContext(context.Background())
}

func (i SenderMap) ToSenderMapOutputWithContext(ctx context.Context) SenderMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SenderMapOutput)
}

type SenderOutput struct{ *pulumi.OutputState }

func (SenderOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Sender)(nil)).Elem()
}

func (o SenderOutput) ToSenderOutput() SenderOutput {
	return o
}

func (o SenderOutput) ToSenderOutputWithContext(ctx context.Context) SenderOutput {
	return o
}

// (Updatable) The OCID of the compartment that contains the sender.
func (o SenderOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *Sender) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
func (o SenderOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *Sender) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
}

// The email address of the sender.
func (o SenderOutput) EmailAddress() pulumi.StringOutput {
	return o.ApplyT(func(v *Sender) pulumi.StringOutput { return v.EmailAddress }).(pulumi.StringOutput)
}

// The email domain used to assert responsibility for emails sent from this sender.
func (o SenderOutput) EmailDomainId() pulumi.StringOutput {
	return o.ApplyT(func(v *Sender) pulumi.StringOutput { return v.EmailDomainId }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o SenderOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *Sender) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// Value of the SPF field. For more information about SPF, please see [SPF Authentication](https://docs.cloud.oracle.com/iaas/Content/Email/Concepts/overview.htm#components).
func (o SenderOutput) IsSpf() pulumi.BoolOutput {
	return o.ApplyT(func(v *Sender) pulumi.BoolOutput { return v.IsSpf }).(pulumi.BoolOutput)
}

// The current status of the approved sender.
func (o SenderOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *Sender) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The date and time the approved sender was added in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
func (o SenderOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *Sender) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

type SenderArrayOutput struct{ *pulumi.OutputState }

func (SenderArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Sender)(nil)).Elem()
}

func (o SenderArrayOutput) ToSenderArrayOutput() SenderArrayOutput {
	return o
}

func (o SenderArrayOutput) ToSenderArrayOutputWithContext(ctx context.Context) SenderArrayOutput {
	return o
}

func (o SenderArrayOutput) Index(i pulumi.IntInput) SenderOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Sender {
		return vs[0].([]*Sender)[vs[1].(int)]
	}).(SenderOutput)
}

type SenderMapOutput struct{ *pulumi.OutputState }

func (SenderMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Sender)(nil)).Elem()
}

func (o SenderMapOutput) ToSenderMapOutput() SenderMapOutput {
	return o
}

func (o SenderMapOutput) ToSenderMapOutputWithContext(ctx context.Context) SenderMapOutput {
	return o
}

func (o SenderMapOutput) MapIndex(k pulumi.StringInput) SenderOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Sender {
		return vs[0].(map[string]*Sender)[vs[1].(string)]
	}).(SenderOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*SenderInput)(nil)).Elem(), &Sender{})
	pulumi.RegisterInputType(reflect.TypeOf((*SenderArrayInput)(nil)).Elem(), SenderArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*SenderMapInput)(nil)).Elem(), SenderMap{})
	pulumi.RegisterOutputType(SenderOutput{})
	pulumi.RegisterOutputType(SenderArrayOutput{})
	pulumi.RegisterOutputType(SenderMapOutput{})
}