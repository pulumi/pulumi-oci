// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Generate On Prem Connector Configuration resource in Oracle Cloud Infrastructure Data Safe service.
//
// Creates and downloads the configuration of the specified on-premises connector.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/datasafe"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := datasafe.NewGenerateOnPremConnectorConfiguration(ctx, "test_generate_on_prem_connector_configuration", &datasafe.GenerateOnPremConnectorConfigurationArgs{
//				OnPremConnectorId: pulumi.Any(testOnPremConnector.Id),
//				Password:          pulumi.Any(generateOnPremConnectorConfigurationPassword),
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
// GenerateOnPremConnectorConfiguration can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:DataSafe/generateOnPremConnectorConfiguration:GenerateOnPremConnectorConfiguration test_generate_on_prem_connector_configuration "id"
// ```
type GenerateOnPremConnectorConfiguration struct {
	pulumi.CustomResourceState

	// The OCID of the on-premises connector.
	OnPremConnectorId pulumi.StringOutput `pulumi:"onPremConnectorId"`
	// The password to encrypt the keys inside the wallet included as part of the configuration. The password must be between 12 and 30 characters long and must contain atleast 1 uppercase, 1 lowercase, 1 numeric, and 1 special character.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Password pulumi.StringOutput `pulumi:"password"`
}

// NewGenerateOnPremConnectorConfiguration registers a new resource with the given unique name, arguments, and options.
func NewGenerateOnPremConnectorConfiguration(ctx *pulumi.Context,
	name string, args *GenerateOnPremConnectorConfigurationArgs, opts ...pulumi.ResourceOption) (*GenerateOnPremConnectorConfiguration, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.OnPremConnectorId == nil {
		return nil, errors.New("invalid value for required argument 'OnPremConnectorId'")
	}
	if args.Password == nil {
		return nil, errors.New("invalid value for required argument 'Password'")
	}
	if args.Password != nil {
		args.Password = pulumi.ToSecret(args.Password).(pulumi.StringInput)
	}
	secrets := pulumi.AdditionalSecretOutputs([]string{
		"password",
	})
	opts = append(opts, secrets)
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource GenerateOnPremConnectorConfiguration
	err := ctx.RegisterResource("oci:DataSafe/generateOnPremConnectorConfiguration:GenerateOnPremConnectorConfiguration", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetGenerateOnPremConnectorConfiguration gets an existing GenerateOnPremConnectorConfiguration resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetGenerateOnPremConnectorConfiguration(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *GenerateOnPremConnectorConfigurationState, opts ...pulumi.ResourceOption) (*GenerateOnPremConnectorConfiguration, error) {
	var resource GenerateOnPremConnectorConfiguration
	err := ctx.ReadResource("oci:DataSafe/generateOnPremConnectorConfiguration:GenerateOnPremConnectorConfiguration", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering GenerateOnPremConnectorConfiguration resources.
type generateOnPremConnectorConfigurationState struct {
	// The OCID of the on-premises connector.
	OnPremConnectorId *string `pulumi:"onPremConnectorId"`
	// The password to encrypt the keys inside the wallet included as part of the configuration. The password must be between 12 and 30 characters long and must contain atleast 1 uppercase, 1 lowercase, 1 numeric, and 1 special character.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Password *string `pulumi:"password"`
}

type GenerateOnPremConnectorConfigurationState struct {
	// The OCID of the on-premises connector.
	OnPremConnectorId pulumi.StringPtrInput
	// The password to encrypt the keys inside the wallet included as part of the configuration. The password must be between 12 and 30 characters long and must contain atleast 1 uppercase, 1 lowercase, 1 numeric, and 1 special character.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Password pulumi.StringPtrInput
}

func (GenerateOnPremConnectorConfigurationState) ElementType() reflect.Type {
	return reflect.TypeOf((*generateOnPremConnectorConfigurationState)(nil)).Elem()
}

type generateOnPremConnectorConfigurationArgs struct {
	// The OCID of the on-premises connector.
	OnPremConnectorId string `pulumi:"onPremConnectorId"`
	// The password to encrypt the keys inside the wallet included as part of the configuration. The password must be between 12 and 30 characters long and must contain atleast 1 uppercase, 1 lowercase, 1 numeric, and 1 special character.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Password string `pulumi:"password"`
}

// The set of arguments for constructing a GenerateOnPremConnectorConfiguration resource.
type GenerateOnPremConnectorConfigurationArgs struct {
	// The OCID of the on-premises connector.
	OnPremConnectorId pulumi.StringInput
	// The password to encrypt the keys inside the wallet included as part of the configuration. The password must be between 12 and 30 characters long and must contain atleast 1 uppercase, 1 lowercase, 1 numeric, and 1 special character.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Password pulumi.StringInput
}

func (GenerateOnPremConnectorConfigurationArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*generateOnPremConnectorConfigurationArgs)(nil)).Elem()
}

type GenerateOnPremConnectorConfigurationInput interface {
	pulumi.Input

	ToGenerateOnPremConnectorConfigurationOutput() GenerateOnPremConnectorConfigurationOutput
	ToGenerateOnPremConnectorConfigurationOutputWithContext(ctx context.Context) GenerateOnPremConnectorConfigurationOutput
}

func (*GenerateOnPremConnectorConfiguration) ElementType() reflect.Type {
	return reflect.TypeOf((**GenerateOnPremConnectorConfiguration)(nil)).Elem()
}

func (i *GenerateOnPremConnectorConfiguration) ToGenerateOnPremConnectorConfigurationOutput() GenerateOnPremConnectorConfigurationOutput {
	return i.ToGenerateOnPremConnectorConfigurationOutputWithContext(context.Background())
}

func (i *GenerateOnPremConnectorConfiguration) ToGenerateOnPremConnectorConfigurationOutputWithContext(ctx context.Context) GenerateOnPremConnectorConfigurationOutput {
	return pulumi.ToOutputWithContext(ctx, i).(GenerateOnPremConnectorConfigurationOutput)
}

// GenerateOnPremConnectorConfigurationArrayInput is an input type that accepts GenerateOnPremConnectorConfigurationArray and GenerateOnPremConnectorConfigurationArrayOutput values.
// You can construct a concrete instance of `GenerateOnPremConnectorConfigurationArrayInput` via:
//
//	GenerateOnPremConnectorConfigurationArray{ GenerateOnPremConnectorConfigurationArgs{...} }
type GenerateOnPremConnectorConfigurationArrayInput interface {
	pulumi.Input

	ToGenerateOnPremConnectorConfigurationArrayOutput() GenerateOnPremConnectorConfigurationArrayOutput
	ToGenerateOnPremConnectorConfigurationArrayOutputWithContext(context.Context) GenerateOnPremConnectorConfigurationArrayOutput
}

type GenerateOnPremConnectorConfigurationArray []GenerateOnPremConnectorConfigurationInput

func (GenerateOnPremConnectorConfigurationArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*GenerateOnPremConnectorConfiguration)(nil)).Elem()
}

func (i GenerateOnPremConnectorConfigurationArray) ToGenerateOnPremConnectorConfigurationArrayOutput() GenerateOnPremConnectorConfigurationArrayOutput {
	return i.ToGenerateOnPremConnectorConfigurationArrayOutputWithContext(context.Background())
}

func (i GenerateOnPremConnectorConfigurationArray) ToGenerateOnPremConnectorConfigurationArrayOutputWithContext(ctx context.Context) GenerateOnPremConnectorConfigurationArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(GenerateOnPremConnectorConfigurationArrayOutput)
}

// GenerateOnPremConnectorConfigurationMapInput is an input type that accepts GenerateOnPremConnectorConfigurationMap and GenerateOnPremConnectorConfigurationMapOutput values.
// You can construct a concrete instance of `GenerateOnPremConnectorConfigurationMapInput` via:
//
//	GenerateOnPremConnectorConfigurationMap{ "key": GenerateOnPremConnectorConfigurationArgs{...} }
type GenerateOnPremConnectorConfigurationMapInput interface {
	pulumi.Input

	ToGenerateOnPremConnectorConfigurationMapOutput() GenerateOnPremConnectorConfigurationMapOutput
	ToGenerateOnPremConnectorConfigurationMapOutputWithContext(context.Context) GenerateOnPremConnectorConfigurationMapOutput
}

type GenerateOnPremConnectorConfigurationMap map[string]GenerateOnPremConnectorConfigurationInput

func (GenerateOnPremConnectorConfigurationMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*GenerateOnPremConnectorConfiguration)(nil)).Elem()
}

func (i GenerateOnPremConnectorConfigurationMap) ToGenerateOnPremConnectorConfigurationMapOutput() GenerateOnPremConnectorConfigurationMapOutput {
	return i.ToGenerateOnPremConnectorConfigurationMapOutputWithContext(context.Background())
}

func (i GenerateOnPremConnectorConfigurationMap) ToGenerateOnPremConnectorConfigurationMapOutputWithContext(ctx context.Context) GenerateOnPremConnectorConfigurationMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(GenerateOnPremConnectorConfigurationMapOutput)
}

type GenerateOnPremConnectorConfigurationOutput struct{ *pulumi.OutputState }

func (GenerateOnPremConnectorConfigurationOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**GenerateOnPremConnectorConfiguration)(nil)).Elem()
}

func (o GenerateOnPremConnectorConfigurationOutput) ToGenerateOnPremConnectorConfigurationOutput() GenerateOnPremConnectorConfigurationOutput {
	return o
}

func (o GenerateOnPremConnectorConfigurationOutput) ToGenerateOnPremConnectorConfigurationOutputWithContext(ctx context.Context) GenerateOnPremConnectorConfigurationOutput {
	return o
}

// The OCID of the on-premises connector.
func (o GenerateOnPremConnectorConfigurationOutput) OnPremConnectorId() pulumi.StringOutput {
	return o.ApplyT(func(v *GenerateOnPremConnectorConfiguration) pulumi.StringOutput { return v.OnPremConnectorId }).(pulumi.StringOutput)
}

// The password to encrypt the keys inside the wallet included as part of the configuration. The password must be between 12 and 30 characters long and must contain atleast 1 uppercase, 1 lowercase, 1 numeric, and 1 special character.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o GenerateOnPremConnectorConfigurationOutput) Password() pulumi.StringOutput {
	return o.ApplyT(func(v *GenerateOnPremConnectorConfiguration) pulumi.StringOutput { return v.Password }).(pulumi.StringOutput)
}

type GenerateOnPremConnectorConfigurationArrayOutput struct{ *pulumi.OutputState }

func (GenerateOnPremConnectorConfigurationArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*GenerateOnPremConnectorConfiguration)(nil)).Elem()
}

func (o GenerateOnPremConnectorConfigurationArrayOutput) ToGenerateOnPremConnectorConfigurationArrayOutput() GenerateOnPremConnectorConfigurationArrayOutput {
	return o
}

func (o GenerateOnPremConnectorConfigurationArrayOutput) ToGenerateOnPremConnectorConfigurationArrayOutputWithContext(ctx context.Context) GenerateOnPremConnectorConfigurationArrayOutput {
	return o
}

func (o GenerateOnPremConnectorConfigurationArrayOutput) Index(i pulumi.IntInput) GenerateOnPremConnectorConfigurationOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *GenerateOnPremConnectorConfiguration {
		return vs[0].([]*GenerateOnPremConnectorConfiguration)[vs[1].(int)]
	}).(GenerateOnPremConnectorConfigurationOutput)
}

type GenerateOnPremConnectorConfigurationMapOutput struct{ *pulumi.OutputState }

func (GenerateOnPremConnectorConfigurationMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*GenerateOnPremConnectorConfiguration)(nil)).Elem()
}

func (o GenerateOnPremConnectorConfigurationMapOutput) ToGenerateOnPremConnectorConfigurationMapOutput() GenerateOnPremConnectorConfigurationMapOutput {
	return o
}

func (o GenerateOnPremConnectorConfigurationMapOutput) ToGenerateOnPremConnectorConfigurationMapOutputWithContext(ctx context.Context) GenerateOnPremConnectorConfigurationMapOutput {
	return o
}

func (o GenerateOnPremConnectorConfigurationMapOutput) MapIndex(k pulumi.StringInput) GenerateOnPremConnectorConfigurationOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *GenerateOnPremConnectorConfiguration {
		return vs[0].(map[string]*GenerateOnPremConnectorConfiguration)[vs[1].(string)]
	}).(GenerateOnPremConnectorConfigurationOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*GenerateOnPremConnectorConfigurationInput)(nil)).Elem(), &GenerateOnPremConnectorConfiguration{})
	pulumi.RegisterInputType(reflect.TypeOf((*GenerateOnPremConnectorConfigurationArrayInput)(nil)).Elem(), GenerateOnPremConnectorConfigurationArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*GenerateOnPremConnectorConfigurationMapInput)(nil)).Elem(), GenerateOnPremConnectorConfigurationMap{})
	pulumi.RegisterOutputType(GenerateOnPremConnectorConfigurationOutput{})
	pulumi.RegisterOutputType(GenerateOnPremConnectorConfigurationArrayOutput{})
	pulumi.RegisterOutputType(GenerateOnPremConnectorConfigurationMapOutput{})
}
