// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package waas

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Http Redirect resource in Oracle Cloud Infrastructure Web Application Acceleration and Security service.
//
// Creates a new HTTP Redirect on the WAF edge.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Waas"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Waas.NewHttpRedirect(ctx, "testHttpRedirect", &Waas.HttpRedirectArgs{
//				CompartmentId: pulumi.Any(_var.Compartment_id),
//				Domain:        pulumi.Any(_var.Http_redirect_domain),
//				Target: &waas.HttpRedirectTargetArgs{
//					Host:     pulumi.Any(_var.Http_redirect_target_host),
//					Path:     pulumi.Any(_var.Http_redirect_target_path),
//					Protocol: pulumi.Any(_var.Http_redirect_target_protocol),
//					Query:    pulumi.Any(_var.Http_redirect_target_query),
//					Port:     pulumi.Any(_var.Http_redirect_target_port),
//				},
//				DefinedTags: pulumi.AnyMap{
//					"Operations.CostCenter": pulumi.Any("42"),
//				},
//				DisplayName: pulumi.Any(_var.Http_redirect_display_name),
//				FreeformTags: pulumi.AnyMap{
//					"Department": pulumi.Any("Finance"),
//				},
//				ResponseCode: pulumi.Any(_var.Http_redirect_response_code),
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
// HttpRedirects can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:Waas/httpRedirect:HttpRedirect test_http_redirect "id"
//
// ```
type HttpRedirect struct {
	pulumi.CustomResourceState

	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the HTTP Redirects compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) The user-friendly name of the HTTP Redirect. The name can be changed and does not need to be unique.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// The domain from which traffic will be redirected.
	Domain pulumi.StringOutput `pulumi:"domain"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// (Updatable) The response code returned for the redirect to the client. For more information, see [RFC 7231](https://tools.ietf.org/html/rfc7231#section-6.4).
	ResponseCode pulumi.IntOutput `pulumi:"responseCode"`
	// The current lifecycle state of the HTTP Redirect.
	State pulumi.StringOutput `pulumi:"state"`
	// (Updatable) The redirect target object including all the redirect data.
	Target HttpRedirectTargetOutput `pulumi:"target"`
	// The date and time the policy was created, expressed in RFC 3339 timestamp format.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
}

// NewHttpRedirect registers a new resource with the given unique name, arguments, and options.
func NewHttpRedirect(ctx *pulumi.Context,
	name string, args *HttpRedirectArgs, opts ...pulumi.ResourceOption) (*HttpRedirect, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.Domain == nil {
		return nil, errors.New("invalid value for required argument 'Domain'")
	}
	if args.Target == nil {
		return nil, errors.New("invalid value for required argument 'Target'")
	}
	var resource HttpRedirect
	err := ctx.RegisterResource("oci:Waas/httpRedirect:HttpRedirect", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetHttpRedirect gets an existing HttpRedirect resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetHttpRedirect(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *HttpRedirectState, opts ...pulumi.ResourceOption) (*HttpRedirect, error) {
	var resource HttpRedirect
	err := ctx.ReadResource("oci:Waas/httpRedirect:HttpRedirect", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering HttpRedirect resources.
type httpRedirectState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the HTTP Redirects compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) The user-friendly name of the HTTP Redirect. The name can be changed and does not need to be unique.
	DisplayName *string `pulumi:"displayName"`
	// The domain from which traffic will be redirected.
	Domain *string `pulumi:"domain"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) The response code returned for the redirect to the client. For more information, see [RFC 7231](https://tools.ietf.org/html/rfc7231#section-6.4).
	ResponseCode *int `pulumi:"responseCode"`
	// The current lifecycle state of the HTTP Redirect.
	State *string `pulumi:"state"`
	// (Updatable) The redirect target object including all the redirect data.
	Target *HttpRedirectTarget `pulumi:"target"`
	// The date and time the policy was created, expressed in RFC 3339 timestamp format.
	TimeCreated *string `pulumi:"timeCreated"`
}

type HttpRedirectState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the HTTP Redirects compartment.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) The user-friendly name of the HTTP Redirect. The name can be changed and does not need to be unique.
	DisplayName pulumi.StringPtrInput
	// The domain from which traffic will be redirected.
	Domain pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// (Updatable) The response code returned for the redirect to the client. For more information, see [RFC 7231](https://tools.ietf.org/html/rfc7231#section-6.4).
	ResponseCode pulumi.IntPtrInput
	// The current lifecycle state of the HTTP Redirect.
	State pulumi.StringPtrInput
	// (Updatable) The redirect target object including all the redirect data.
	Target HttpRedirectTargetPtrInput
	// The date and time the policy was created, expressed in RFC 3339 timestamp format.
	TimeCreated pulumi.StringPtrInput
}

func (HttpRedirectState) ElementType() reflect.Type {
	return reflect.TypeOf((*httpRedirectState)(nil)).Elem()
}

type httpRedirectArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the HTTP Redirects compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) The user-friendly name of the HTTP Redirect. The name can be changed and does not need to be unique.
	DisplayName *string `pulumi:"displayName"`
	// The domain from which traffic will be redirected.
	Domain string `pulumi:"domain"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) The response code returned for the redirect to the client. For more information, see [RFC 7231](https://tools.ietf.org/html/rfc7231#section-6.4).
	ResponseCode *int `pulumi:"responseCode"`
	// (Updatable) The redirect target object including all the redirect data.
	Target HttpRedirectTarget `pulumi:"target"`
}

// The set of arguments for constructing a HttpRedirect resource.
type HttpRedirectArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the HTTP Redirects compartment.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) The user-friendly name of the HTTP Redirect. The name can be changed and does not need to be unique.
	DisplayName pulumi.StringPtrInput
	// The domain from which traffic will be redirected.
	Domain pulumi.StringInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// (Updatable) The response code returned for the redirect to the client. For more information, see [RFC 7231](https://tools.ietf.org/html/rfc7231#section-6.4).
	ResponseCode pulumi.IntPtrInput
	// (Updatable) The redirect target object including all the redirect data.
	Target HttpRedirectTargetInput
}

func (HttpRedirectArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*httpRedirectArgs)(nil)).Elem()
}

type HttpRedirectInput interface {
	pulumi.Input

	ToHttpRedirectOutput() HttpRedirectOutput
	ToHttpRedirectOutputWithContext(ctx context.Context) HttpRedirectOutput
}

func (*HttpRedirect) ElementType() reflect.Type {
	return reflect.TypeOf((**HttpRedirect)(nil)).Elem()
}

func (i *HttpRedirect) ToHttpRedirectOutput() HttpRedirectOutput {
	return i.ToHttpRedirectOutputWithContext(context.Background())
}

func (i *HttpRedirect) ToHttpRedirectOutputWithContext(ctx context.Context) HttpRedirectOutput {
	return pulumi.ToOutputWithContext(ctx, i).(HttpRedirectOutput)
}

// HttpRedirectArrayInput is an input type that accepts HttpRedirectArray and HttpRedirectArrayOutput values.
// You can construct a concrete instance of `HttpRedirectArrayInput` via:
//
//	HttpRedirectArray{ HttpRedirectArgs{...} }
type HttpRedirectArrayInput interface {
	pulumi.Input

	ToHttpRedirectArrayOutput() HttpRedirectArrayOutput
	ToHttpRedirectArrayOutputWithContext(context.Context) HttpRedirectArrayOutput
}

type HttpRedirectArray []HttpRedirectInput

func (HttpRedirectArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*HttpRedirect)(nil)).Elem()
}

func (i HttpRedirectArray) ToHttpRedirectArrayOutput() HttpRedirectArrayOutput {
	return i.ToHttpRedirectArrayOutputWithContext(context.Background())
}

func (i HttpRedirectArray) ToHttpRedirectArrayOutputWithContext(ctx context.Context) HttpRedirectArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(HttpRedirectArrayOutput)
}

// HttpRedirectMapInput is an input type that accepts HttpRedirectMap and HttpRedirectMapOutput values.
// You can construct a concrete instance of `HttpRedirectMapInput` via:
//
//	HttpRedirectMap{ "key": HttpRedirectArgs{...} }
type HttpRedirectMapInput interface {
	pulumi.Input

	ToHttpRedirectMapOutput() HttpRedirectMapOutput
	ToHttpRedirectMapOutputWithContext(context.Context) HttpRedirectMapOutput
}

type HttpRedirectMap map[string]HttpRedirectInput

func (HttpRedirectMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*HttpRedirect)(nil)).Elem()
}

func (i HttpRedirectMap) ToHttpRedirectMapOutput() HttpRedirectMapOutput {
	return i.ToHttpRedirectMapOutputWithContext(context.Background())
}

func (i HttpRedirectMap) ToHttpRedirectMapOutputWithContext(ctx context.Context) HttpRedirectMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(HttpRedirectMapOutput)
}

type HttpRedirectOutput struct{ *pulumi.OutputState }

func (HttpRedirectOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**HttpRedirect)(nil)).Elem()
}

func (o HttpRedirectOutput) ToHttpRedirectOutput() HttpRedirectOutput {
	return o
}

func (o HttpRedirectOutput) ToHttpRedirectOutputWithContext(ctx context.Context) HttpRedirectOutput {
	return o
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the HTTP Redirects compartment.
func (o HttpRedirectOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *HttpRedirect) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
func (o HttpRedirectOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *HttpRedirect) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
}

// (Updatable) The user-friendly name of the HTTP Redirect. The name can be changed and does not need to be unique.
func (o HttpRedirectOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *HttpRedirect) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// The domain from which traffic will be redirected.
func (o HttpRedirectOutput) Domain() pulumi.StringOutput {
	return o.ApplyT(func(v *HttpRedirect) pulumi.StringOutput { return v.Domain }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o HttpRedirectOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *HttpRedirect) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// (Updatable) The response code returned for the redirect to the client. For more information, see [RFC 7231](https://tools.ietf.org/html/rfc7231#section-6.4).
func (o HttpRedirectOutput) ResponseCode() pulumi.IntOutput {
	return o.ApplyT(func(v *HttpRedirect) pulumi.IntOutput { return v.ResponseCode }).(pulumi.IntOutput)
}

// The current lifecycle state of the HTTP Redirect.
func (o HttpRedirectOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *HttpRedirect) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// (Updatable) The redirect target object including all the redirect data.
func (o HttpRedirectOutput) Target() HttpRedirectTargetOutput {
	return o.ApplyT(func(v *HttpRedirect) HttpRedirectTargetOutput { return v.Target }).(HttpRedirectTargetOutput)
}

// The date and time the policy was created, expressed in RFC 3339 timestamp format.
func (o HttpRedirectOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *HttpRedirect) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

type HttpRedirectArrayOutput struct{ *pulumi.OutputState }

func (HttpRedirectArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*HttpRedirect)(nil)).Elem()
}

func (o HttpRedirectArrayOutput) ToHttpRedirectArrayOutput() HttpRedirectArrayOutput {
	return o
}

func (o HttpRedirectArrayOutput) ToHttpRedirectArrayOutputWithContext(ctx context.Context) HttpRedirectArrayOutput {
	return o
}

func (o HttpRedirectArrayOutput) Index(i pulumi.IntInput) HttpRedirectOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *HttpRedirect {
		return vs[0].([]*HttpRedirect)[vs[1].(int)]
	}).(HttpRedirectOutput)
}

type HttpRedirectMapOutput struct{ *pulumi.OutputState }

func (HttpRedirectMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*HttpRedirect)(nil)).Elem()
}

func (o HttpRedirectMapOutput) ToHttpRedirectMapOutput() HttpRedirectMapOutput {
	return o
}

func (o HttpRedirectMapOutput) ToHttpRedirectMapOutputWithContext(ctx context.Context) HttpRedirectMapOutput {
	return o
}

func (o HttpRedirectMapOutput) MapIndex(k pulumi.StringInput) HttpRedirectOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *HttpRedirect {
		return vs[0].(map[string]*HttpRedirect)[vs[1].(string)]
	}).(HttpRedirectOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*HttpRedirectInput)(nil)).Elem(), &HttpRedirect{})
	pulumi.RegisterInputType(reflect.TypeOf((*HttpRedirectArrayInput)(nil)).Elem(), HttpRedirectArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*HttpRedirectMapInput)(nil)).Elem(), HttpRedirectMap{})
	pulumi.RegisterOutputType(HttpRedirectOutput{})
	pulumi.RegisterOutputType(HttpRedirectArrayOutput{})
	pulumi.RegisterOutputType(HttpRedirectMapOutput{})
}