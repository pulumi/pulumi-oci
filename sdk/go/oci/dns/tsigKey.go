// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package dns

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Tsig Key resource in Oracle Cloud Infrastructure DNS service.
//
// Creates a new TSIG key in the specified compartment. There is no
// `opc-retry-token` header since TSIG key names must be globally unique.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Dns"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Dns.NewTsigKey(ctx, "testTsigKey", &Dns.TsigKeyArgs{
//				Algorithm:     pulumi.Any(_var.Tsig_key_algorithm),
//				CompartmentId: pulumi.Any(_var.Compartment_id),
//				Secret:        pulumi.Any(_var.Tsig_key_secret),
//				DefinedTags:   pulumi.Any(_var.Tsig_key_defined_tags),
//				FreeformTags:  pulumi.Any(_var.Tsig_key_freeform_tags),
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
// TsigKeys can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:Dns/tsigKey:TsigKey test_tsig_key "id"
//
// ```
type TsigKey struct {
	pulumi.CustomResourceState

	// TSIG key algorithms are encoded as domain names, but most consist of only one non-empty label, which is not required to be explicitly absolute. Applicable algorithms include: hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha512. For more information on these algorithms, see [RFC 4635](https://tools.ietf.org/html/rfc4635#section-2).
	Algorithm pulumi.StringOutput `pulumi:"algorithm"`
	// (Updatable) The OCID of the compartment containing the TSIG key.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// A globally unique domain name identifying the key for a given pair of hosts.
	Name pulumi.StringOutput `pulumi:"name"`
	// A base64 string encoding the binary shared secret.
	Secret pulumi.StringOutput `pulumi:"secret"`
	// The canonical absolute URL of the resource.
	Self pulumi.StringOutput `pulumi:"self"`
	// The current state of the resource.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the resource was created, expressed in RFC 3339 timestamp format.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time the resource was last updated, expressed in RFC 3339 timestamp format.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewTsigKey registers a new resource with the given unique name, arguments, and options.
func NewTsigKey(ctx *pulumi.Context,
	name string, args *TsigKeyArgs, opts ...pulumi.ResourceOption) (*TsigKey, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.Algorithm == nil {
		return nil, errors.New("invalid value for required argument 'Algorithm'")
	}
	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.Secret == nil {
		return nil, errors.New("invalid value for required argument 'Secret'")
	}
	var resource TsigKey
	err := ctx.RegisterResource("oci:Dns/tsigKey:TsigKey", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetTsigKey gets an existing TsigKey resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetTsigKey(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *TsigKeyState, opts ...pulumi.ResourceOption) (*TsigKey, error) {
	var resource TsigKey
	err := ctx.ReadResource("oci:Dns/tsigKey:TsigKey", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering TsigKey resources.
type tsigKeyState struct {
	// TSIG key algorithms are encoded as domain names, but most consist of only one non-empty label, which is not required to be explicitly absolute. Applicable algorithms include: hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha512. For more information on these algorithms, see [RFC 4635](https://tools.ietf.org/html/rfc4635#section-2).
	Algorithm *string `pulumi:"algorithm"`
	// (Updatable) The OCID of the compartment containing the TSIG key.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// A globally unique domain name identifying the key for a given pair of hosts.
	Name *string `pulumi:"name"`
	// A base64 string encoding the binary shared secret.
	Secret *string `pulumi:"secret"`
	// The canonical absolute URL of the resource.
	Self *string `pulumi:"self"`
	// The current state of the resource.
	State *string `pulumi:"state"`
	// The date and time the resource was created, expressed in RFC 3339 timestamp format.
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time the resource was last updated, expressed in RFC 3339 timestamp format.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type TsigKeyState struct {
	// TSIG key algorithms are encoded as domain names, but most consist of only one non-empty label, which is not required to be explicitly absolute. Applicable algorithms include: hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha512. For more information on these algorithms, see [RFC 4635](https://tools.ietf.org/html/rfc4635#section-2).
	Algorithm pulumi.StringPtrInput
	// (Updatable) The OCID of the compartment containing the TSIG key.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags pulumi.MapInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	FreeformTags pulumi.MapInput
	// A globally unique domain name identifying the key for a given pair of hosts.
	Name pulumi.StringPtrInput
	// A base64 string encoding the binary shared secret.
	Secret pulumi.StringPtrInput
	// The canonical absolute URL of the resource.
	Self pulumi.StringPtrInput
	// The current state of the resource.
	State pulumi.StringPtrInput
	// The date and time the resource was created, expressed in RFC 3339 timestamp format.
	TimeCreated pulumi.StringPtrInput
	// The date and time the resource was last updated, expressed in RFC 3339 timestamp format.
	TimeUpdated pulumi.StringPtrInput
}

func (TsigKeyState) ElementType() reflect.Type {
	return reflect.TypeOf((*tsigKeyState)(nil)).Elem()
}

type tsigKeyArgs struct {
	// TSIG key algorithms are encoded as domain names, but most consist of only one non-empty label, which is not required to be explicitly absolute. Applicable algorithms include: hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha512. For more information on these algorithms, see [RFC 4635](https://tools.ietf.org/html/rfc4635#section-2).
	Algorithm string `pulumi:"algorithm"`
	// (Updatable) The OCID of the compartment containing the TSIG key.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// A globally unique domain name identifying the key for a given pair of hosts.
	Name *string `pulumi:"name"`
	// A base64 string encoding the binary shared secret.
	Secret string `pulumi:"secret"`
}

// The set of arguments for constructing a TsigKey resource.
type TsigKeyArgs struct {
	// TSIG key algorithms are encoded as domain names, but most consist of only one non-empty label, which is not required to be explicitly absolute. Applicable algorithms include: hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha512. For more information on these algorithms, see [RFC 4635](https://tools.ietf.org/html/rfc4635#section-2).
	Algorithm pulumi.StringInput
	// (Updatable) The OCID of the compartment containing the TSIG key.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags pulumi.MapInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	FreeformTags pulumi.MapInput
	// A globally unique domain name identifying the key for a given pair of hosts.
	Name pulumi.StringPtrInput
	// A base64 string encoding the binary shared secret.
	Secret pulumi.StringInput
}

func (TsigKeyArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*tsigKeyArgs)(nil)).Elem()
}

type TsigKeyInput interface {
	pulumi.Input

	ToTsigKeyOutput() TsigKeyOutput
	ToTsigKeyOutputWithContext(ctx context.Context) TsigKeyOutput
}

func (*TsigKey) ElementType() reflect.Type {
	return reflect.TypeOf((**TsigKey)(nil)).Elem()
}

func (i *TsigKey) ToTsigKeyOutput() TsigKeyOutput {
	return i.ToTsigKeyOutputWithContext(context.Background())
}

func (i *TsigKey) ToTsigKeyOutputWithContext(ctx context.Context) TsigKeyOutput {
	return pulumi.ToOutputWithContext(ctx, i).(TsigKeyOutput)
}

// TsigKeyArrayInput is an input type that accepts TsigKeyArray and TsigKeyArrayOutput values.
// You can construct a concrete instance of `TsigKeyArrayInput` via:
//
//	TsigKeyArray{ TsigKeyArgs{...} }
type TsigKeyArrayInput interface {
	pulumi.Input

	ToTsigKeyArrayOutput() TsigKeyArrayOutput
	ToTsigKeyArrayOutputWithContext(context.Context) TsigKeyArrayOutput
}

type TsigKeyArray []TsigKeyInput

func (TsigKeyArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*TsigKey)(nil)).Elem()
}

func (i TsigKeyArray) ToTsigKeyArrayOutput() TsigKeyArrayOutput {
	return i.ToTsigKeyArrayOutputWithContext(context.Background())
}

func (i TsigKeyArray) ToTsigKeyArrayOutputWithContext(ctx context.Context) TsigKeyArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(TsigKeyArrayOutput)
}

// TsigKeyMapInput is an input type that accepts TsigKeyMap and TsigKeyMapOutput values.
// You can construct a concrete instance of `TsigKeyMapInput` via:
//
//	TsigKeyMap{ "key": TsigKeyArgs{...} }
type TsigKeyMapInput interface {
	pulumi.Input

	ToTsigKeyMapOutput() TsigKeyMapOutput
	ToTsigKeyMapOutputWithContext(context.Context) TsigKeyMapOutput
}

type TsigKeyMap map[string]TsigKeyInput

func (TsigKeyMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*TsigKey)(nil)).Elem()
}

func (i TsigKeyMap) ToTsigKeyMapOutput() TsigKeyMapOutput {
	return i.ToTsigKeyMapOutputWithContext(context.Background())
}

func (i TsigKeyMap) ToTsigKeyMapOutputWithContext(ctx context.Context) TsigKeyMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(TsigKeyMapOutput)
}

type TsigKeyOutput struct{ *pulumi.OutputState }

func (TsigKeyOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**TsigKey)(nil)).Elem()
}

func (o TsigKeyOutput) ToTsigKeyOutput() TsigKeyOutput {
	return o
}

func (o TsigKeyOutput) ToTsigKeyOutputWithContext(ctx context.Context) TsigKeyOutput {
	return o
}

// TSIG key algorithms are encoded as domain names, but most consist of only one non-empty label, which is not required to be explicitly absolute. Applicable algorithms include: hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha512. For more information on these algorithms, see [RFC 4635](https://tools.ietf.org/html/rfc4635#section-2).
func (o TsigKeyOutput) Algorithm() pulumi.StringOutput {
	return o.ApplyT(func(v *TsigKey) pulumi.StringOutput { return v.Algorithm }).(pulumi.StringOutput)
}

// (Updatable) The OCID of the compartment containing the TSIG key.
func (o TsigKeyOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *TsigKey) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
func (o TsigKeyOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *TsigKey) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
func (o TsigKeyOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *TsigKey) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// A globally unique domain name identifying the key for a given pair of hosts.
func (o TsigKeyOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v *TsigKey) pulumi.StringOutput { return v.Name }).(pulumi.StringOutput)
}

// A base64 string encoding the binary shared secret.
func (o TsigKeyOutput) Secret() pulumi.StringOutput {
	return o.ApplyT(func(v *TsigKey) pulumi.StringOutput { return v.Secret }).(pulumi.StringOutput)
}

// The canonical absolute URL of the resource.
func (o TsigKeyOutput) Self() pulumi.StringOutput {
	return o.ApplyT(func(v *TsigKey) pulumi.StringOutput { return v.Self }).(pulumi.StringOutput)
}

// The current state of the resource.
func (o TsigKeyOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *TsigKey) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The date and time the resource was created, expressed in RFC 3339 timestamp format.
func (o TsigKeyOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *TsigKey) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the resource was last updated, expressed in RFC 3339 timestamp format.
func (o TsigKeyOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *TsigKey) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type TsigKeyArrayOutput struct{ *pulumi.OutputState }

func (TsigKeyArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*TsigKey)(nil)).Elem()
}

func (o TsigKeyArrayOutput) ToTsigKeyArrayOutput() TsigKeyArrayOutput {
	return o
}

func (o TsigKeyArrayOutput) ToTsigKeyArrayOutputWithContext(ctx context.Context) TsigKeyArrayOutput {
	return o
}

func (o TsigKeyArrayOutput) Index(i pulumi.IntInput) TsigKeyOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *TsigKey {
		return vs[0].([]*TsigKey)[vs[1].(int)]
	}).(TsigKeyOutput)
}

type TsigKeyMapOutput struct{ *pulumi.OutputState }

func (TsigKeyMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*TsigKey)(nil)).Elem()
}

func (o TsigKeyMapOutput) ToTsigKeyMapOutput() TsigKeyMapOutput {
	return o
}

func (o TsigKeyMapOutput) ToTsigKeyMapOutputWithContext(ctx context.Context) TsigKeyMapOutput {
	return o
}

func (o TsigKeyMapOutput) MapIndex(k pulumi.StringInput) TsigKeyOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *TsigKey {
		return vs[0].(map[string]*TsigKey)[vs[1].(string)]
	}).(TsigKeyOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*TsigKeyInput)(nil)).Elem(), &TsigKey{})
	pulumi.RegisterInputType(reflect.TypeOf((*TsigKeyArrayInput)(nil)).Elem(), TsigKeyArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*TsigKeyMapInput)(nil)).Elem(), TsigKeyMap{})
	pulumi.RegisterOutputType(TsigKeyOutput{})
	pulumi.RegisterOutputType(TsigKeyArrayOutput{})
	pulumi.RegisterOutputType(TsigKeyMapOutput{})
}