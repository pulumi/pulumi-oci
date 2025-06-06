// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the User Capabilities Management resource in Oracle Cloud Infrastructure Identity service.
//
// Manages the capabilities of the specified user.
//
// **Important:** Deleting the User Capabilities Management leaves the User resource in its existing state (rather than returning to its defaults)
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/identity"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := identity.NewUserCapabilitiesManagement(ctx, "test_user_capabilities_management", &identity.UserCapabilitiesManagementArgs{
//				UserId:                   pulumi.Any(user1.Id),
//				CanUseApiKeys:            pulumi.Bool(true),
//				CanUseAuthTokens:         pulumi.Bool(true),
//				CanUseConsolePassword:    pulumi.Bool(false),
//				CanUseCustomerSecretKeys: pulumi.Bool(true),
//				CanUseSmtpCredentials:    pulumi.Bool(true),
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
// Users can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:Identity/userCapabilitiesManagement:UserCapabilitiesManagement test_user_capabilities_management "capabilities/{userId}"
// ```
type UserCapabilitiesManagement struct {
	pulumi.CustomResourceState

	// (Updatable) Indicates if the user can use API keys.
	CanUseApiKeys pulumi.BoolOutput `pulumi:"canUseApiKeys"`
	// (Updatable) Indicates if the user can use SWIFT passwords / auth tokens.
	CanUseAuthTokens pulumi.BoolOutput `pulumi:"canUseAuthTokens"`
	// (Updatable) Indicates if the user can log in to the console.
	CanUseConsolePassword pulumi.BoolOutput `pulumi:"canUseConsolePassword"`
	// (Updatable) Indicates if the user can use SigV4 symmetric keys.
	CanUseCustomerSecretKeys pulumi.BoolOutput `pulumi:"canUseCustomerSecretKeys"`
	// (Updatable) Indicates if the user can use SMTP passwords.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	CanUseSmtpCredentials pulumi.BoolOutput `pulumi:"canUseSmtpCredentials"`
	// The OCID of the user.
	UserId pulumi.StringOutput `pulumi:"userId"`
}

// NewUserCapabilitiesManagement registers a new resource with the given unique name, arguments, and options.
func NewUserCapabilitiesManagement(ctx *pulumi.Context,
	name string, args *UserCapabilitiesManagementArgs, opts ...pulumi.ResourceOption) (*UserCapabilitiesManagement, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.UserId == nil {
		return nil, errors.New("invalid value for required argument 'UserId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource UserCapabilitiesManagement
	err := ctx.RegisterResource("oci:Identity/userCapabilitiesManagement:UserCapabilitiesManagement", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetUserCapabilitiesManagement gets an existing UserCapabilitiesManagement resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetUserCapabilitiesManagement(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *UserCapabilitiesManagementState, opts ...pulumi.ResourceOption) (*UserCapabilitiesManagement, error) {
	var resource UserCapabilitiesManagement
	err := ctx.ReadResource("oci:Identity/userCapabilitiesManagement:UserCapabilitiesManagement", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering UserCapabilitiesManagement resources.
type userCapabilitiesManagementState struct {
	// (Updatable) Indicates if the user can use API keys.
	CanUseApiKeys *bool `pulumi:"canUseApiKeys"`
	// (Updatable) Indicates if the user can use SWIFT passwords / auth tokens.
	CanUseAuthTokens *bool `pulumi:"canUseAuthTokens"`
	// (Updatable) Indicates if the user can log in to the console.
	CanUseConsolePassword *bool `pulumi:"canUseConsolePassword"`
	// (Updatable) Indicates if the user can use SigV4 symmetric keys.
	CanUseCustomerSecretKeys *bool `pulumi:"canUseCustomerSecretKeys"`
	// (Updatable) Indicates if the user can use SMTP passwords.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	CanUseSmtpCredentials *bool `pulumi:"canUseSmtpCredentials"`
	// The OCID of the user.
	UserId *string `pulumi:"userId"`
}

type UserCapabilitiesManagementState struct {
	// (Updatable) Indicates if the user can use API keys.
	CanUseApiKeys pulumi.BoolPtrInput
	// (Updatable) Indicates if the user can use SWIFT passwords / auth tokens.
	CanUseAuthTokens pulumi.BoolPtrInput
	// (Updatable) Indicates if the user can log in to the console.
	CanUseConsolePassword pulumi.BoolPtrInput
	// (Updatable) Indicates if the user can use SigV4 symmetric keys.
	CanUseCustomerSecretKeys pulumi.BoolPtrInput
	// (Updatable) Indicates if the user can use SMTP passwords.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	CanUseSmtpCredentials pulumi.BoolPtrInput
	// The OCID of the user.
	UserId pulumi.StringPtrInput
}

func (UserCapabilitiesManagementState) ElementType() reflect.Type {
	return reflect.TypeOf((*userCapabilitiesManagementState)(nil)).Elem()
}

type userCapabilitiesManagementArgs struct {
	// (Updatable) Indicates if the user can use API keys.
	CanUseApiKeys *bool `pulumi:"canUseApiKeys"`
	// (Updatable) Indicates if the user can use SWIFT passwords / auth tokens.
	CanUseAuthTokens *bool `pulumi:"canUseAuthTokens"`
	// (Updatable) Indicates if the user can log in to the console.
	CanUseConsolePassword *bool `pulumi:"canUseConsolePassword"`
	// (Updatable) Indicates if the user can use SigV4 symmetric keys.
	CanUseCustomerSecretKeys *bool `pulumi:"canUseCustomerSecretKeys"`
	// (Updatable) Indicates if the user can use SMTP passwords.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	CanUseSmtpCredentials *bool `pulumi:"canUseSmtpCredentials"`
	// The OCID of the user.
	UserId string `pulumi:"userId"`
}

// The set of arguments for constructing a UserCapabilitiesManagement resource.
type UserCapabilitiesManagementArgs struct {
	// (Updatable) Indicates if the user can use API keys.
	CanUseApiKeys pulumi.BoolPtrInput
	// (Updatable) Indicates if the user can use SWIFT passwords / auth tokens.
	CanUseAuthTokens pulumi.BoolPtrInput
	// (Updatable) Indicates if the user can log in to the console.
	CanUseConsolePassword pulumi.BoolPtrInput
	// (Updatable) Indicates if the user can use SigV4 symmetric keys.
	CanUseCustomerSecretKeys pulumi.BoolPtrInput
	// (Updatable) Indicates if the user can use SMTP passwords.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	CanUseSmtpCredentials pulumi.BoolPtrInput
	// The OCID of the user.
	UserId pulumi.StringInput
}

func (UserCapabilitiesManagementArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*userCapabilitiesManagementArgs)(nil)).Elem()
}

type UserCapabilitiesManagementInput interface {
	pulumi.Input

	ToUserCapabilitiesManagementOutput() UserCapabilitiesManagementOutput
	ToUserCapabilitiesManagementOutputWithContext(ctx context.Context) UserCapabilitiesManagementOutput
}

func (*UserCapabilitiesManagement) ElementType() reflect.Type {
	return reflect.TypeOf((**UserCapabilitiesManagement)(nil)).Elem()
}

func (i *UserCapabilitiesManagement) ToUserCapabilitiesManagementOutput() UserCapabilitiesManagementOutput {
	return i.ToUserCapabilitiesManagementOutputWithContext(context.Background())
}

func (i *UserCapabilitiesManagement) ToUserCapabilitiesManagementOutputWithContext(ctx context.Context) UserCapabilitiesManagementOutput {
	return pulumi.ToOutputWithContext(ctx, i).(UserCapabilitiesManagementOutput)
}

// UserCapabilitiesManagementArrayInput is an input type that accepts UserCapabilitiesManagementArray and UserCapabilitiesManagementArrayOutput values.
// You can construct a concrete instance of `UserCapabilitiesManagementArrayInput` via:
//
//	UserCapabilitiesManagementArray{ UserCapabilitiesManagementArgs{...} }
type UserCapabilitiesManagementArrayInput interface {
	pulumi.Input

	ToUserCapabilitiesManagementArrayOutput() UserCapabilitiesManagementArrayOutput
	ToUserCapabilitiesManagementArrayOutputWithContext(context.Context) UserCapabilitiesManagementArrayOutput
}

type UserCapabilitiesManagementArray []UserCapabilitiesManagementInput

func (UserCapabilitiesManagementArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*UserCapabilitiesManagement)(nil)).Elem()
}

func (i UserCapabilitiesManagementArray) ToUserCapabilitiesManagementArrayOutput() UserCapabilitiesManagementArrayOutput {
	return i.ToUserCapabilitiesManagementArrayOutputWithContext(context.Background())
}

func (i UserCapabilitiesManagementArray) ToUserCapabilitiesManagementArrayOutputWithContext(ctx context.Context) UserCapabilitiesManagementArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(UserCapabilitiesManagementArrayOutput)
}

// UserCapabilitiesManagementMapInput is an input type that accepts UserCapabilitiesManagementMap and UserCapabilitiesManagementMapOutput values.
// You can construct a concrete instance of `UserCapabilitiesManagementMapInput` via:
//
//	UserCapabilitiesManagementMap{ "key": UserCapabilitiesManagementArgs{...} }
type UserCapabilitiesManagementMapInput interface {
	pulumi.Input

	ToUserCapabilitiesManagementMapOutput() UserCapabilitiesManagementMapOutput
	ToUserCapabilitiesManagementMapOutputWithContext(context.Context) UserCapabilitiesManagementMapOutput
}

type UserCapabilitiesManagementMap map[string]UserCapabilitiesManagementInput

func (UserCapabilitiesManagementMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*UserCapabilitiesManagement)(nil)).Elem()
}

func (i UserCapabilitiesManagementMap) ToUserCapabilitiesManagementMapOutput() UserCapabilitiesManagementMapOutput {
	return i.ToUserCapabilitiesManagementMapOutputWithContext(context.Background())
}

func (i UserCapabilitiesManagementMap) ToUserCapabilitiesManagementMapOutputWithContext(ctx context.Context) UserCapabilitiesManagementMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(UserCapabilitiesManagementMapOutput)
}

type UserCapabilitiesManagementOutput struct{ *pulumi.OutputState }

func (UserCapabilitiesManagementOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**UserCapabilitiesManagement)(nil)).Elem()
}

func (o UserCapabilitiesManagementOutput) ToUserCapabilitiesManagementOutput() UserCapabilitiesManagementOutput {
	return o
}

func (o UserCapabilitiesManagementOutput) ToUserCapabilitiesManagementOutputWithContext(ctx context.Context) UserCapabilitiesManagementOutput {
	return o
}

// (Updatable) Indicates if the user can use API keys.
func (o UserCapabilitiesManagementOutput) CanUseApiKeys() pulumi.BoolOutput {
	return o.ApplyT(func(v *UserCapabilitiesManagement) pulumi.BoolOutput { return v.CanUseApiKeys }).(pulumi.BoolOutput)
}

// (Updatable) Indicates if the user can use SWIFT passwords / auth tokens.
func (o UserCapabilitiesManagementOutput) CanUseAuthTokens() pulumi.BoolOutput {
	return o.ApplyT(func(v *UserCapabilitiesManagement) pulumi.BoolOutput { return v.CanUseAuthTokens }).(pulumi.BoolOutput)
}

// (Updatable) Indicates if the user can log in to the console.
func (o UserCapabilitiesManagementOutput) CanUseConsolePassword() pulumi.BoolOutput {
	return o.ApplyT(func(v *UserCapabilitiesManagement) pulumi.BoolOutput { return v.CanUseConsolePassword }).(pulumi.BoolOutput)
}

// (Updatable) Indicates if the user can use SigV4 symmetric keys.
func (o UserCapabilitiesManagementOutput) CanUseCustomerSecretKeys() pulumi.BoolOutput {
	return o.ApplyT(func(v *UserCapabilitiesManagement) pulumi.BoolOutput { return v.CanUseCustomerSecretKeys }).(pulumi.BoolOutput)
}

// (Updatable) Indicates if the user can use SMTP passwords.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o UserCapabilitiesManagementOutput) CanUseSmtpCredentials() pulumi.BoolOutput {
	return o.ApplyT(func(v *UserCapabilitiesManagement) pulumi.BoolOutput { return v.CanUseSmtpCredentials }).(pulumi.BoolOutput)
}

// The OCID of the user.
func (o UserCapabilitiesManagementOutput) UserId() pulumi.StringOutput {
	return o.ApplyT(func(v *UserCapabilitiesManagement) pulumi.StringOutput { return v.UserId }).(pulumi.StringOutput)
}

type UserCapabilitiesManagementArrayOutput struct{ *pulumi.OutputState }

func (UserCapabilitiesManagementArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*UserCapabilitiesManagement)(nil)).Elem()
}

func (o UserCapabilitiesManagementArrayOutput) ToUserCapabilitiesManagementArrayOutput() UserCapabilitiesManagementArrayOutput {
	return o
}

func (o UserCapabilitiesManagementArrayOutput) ToUserCapabilitiesManagementArrayOutputWithContext(ctx context.Context) UserCapabilitiesManagementArrayOutput {
	return o
}

func (o UserCapabilitiesManagementArrayOutput) Index(i pulumi.IntInput) UserCapabilitiesManagementOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *UserCapabilitiesManagement {
		return vs[0].([]*UserCapabilitiesManagement)[vs[1].(int)]
	}).(UserCapabilitiesManagementOutput)
}

type UserCapabilitiesManagementMapOutput struct{ *pulumi.OutputState }

func (UserCapabilitiesManagementMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*UserCapabilitiesManagement)(nil)).Elem()
}

func (o UserCapabilitiesManagementMapOutput) ToUserCapabilitiesManagementMapOutput() UserCapabilitiesManagementMapOutput {
	return o
}

func (o UserCapabilitiesManagementMapOutput) ToUserCapabilitiesManagementMapOutputWithContext(ctx context.Context) UserCapabilitiesManagementMapOutput {
	return o
}

func (o UserCapabilitiesManagementMapOutput) MapIndex(k pulumi.StringInput) UserCapabilitiesManagementOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *UserCapabilitiesManagement {
		return vs[0].(map[string]*UserCapabilitiesManagement)[vs[1].(string)]
	}).(UserCapabilitiesManagementOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*UserCapabilitiesManagementInput)(nil)).Elem(), &UserCapabilitiesManagement{})
	pulumi.RegisterInputType(reflect.TypeOf((*UserCapabilitiesManagementArrayInput)(nil)).Elem(), UserCapabilitiesManagementArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*UserCapabilitiesManagementMapInput)(nil)).Elem(), UserCapabilitiesManagementMap{})
	pulumi.RegisterOutputType(UserCapabilitiesManagementOutput{})
	pulumi.RegisterOutputType(UserCapabilitiesManagementArrayOutput{})
	pulumi.RegisterOutputType(UserCapabilitiesManagementMapOutput{})
}
