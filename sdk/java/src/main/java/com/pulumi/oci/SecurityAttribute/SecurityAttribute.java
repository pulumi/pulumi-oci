// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.SecurityAttribute;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.SecurityAttribute.SecurityAttributeArgs;
import com.pulumi.oci.SecurityAttribute.inputs.SecurityAttributeState;
import com.pulumi.oci.SecurityAttribute.outputs.SecurityAttributeValidator;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.String;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource provides the Security Attribute resource in Oracle Cloud Infrastructure Security Attribute service.
 * 
 * Creates a new security attribute in the specified security attribute namespace.
 * 
 * The security attribute requires either the OCID or the name of the security attribute namespace that will contain this
 * security attribute.
 * 
 * You must specify a *name* for the attribute, which must be unique across all attributes in the security attribute namespace
 * and cannot be changed. The only valid characters for security attribute names are: 0-9, A-Z, a-z, -, _ characters.
 * Names are case insensitive. That means, for example, &#34;mySecurityAttribute&#34; and &#34;mysecurityattribute&#34; are not allowed in the same namespace.
 * If you specify a name that&#39;s already in use in the security attribute namespace, a 409 error is returned.
 * 
 * The security attribute must have a *description*. It does not have to be unique, and you can change it with
 * [UpdateSecurityAttribute](https://docs.cloud.oracle.com/iaas/api/#/en/securityattribute/latest/Tag/UpdateSecurityAttribute).
 * 
 * When a validator is specified, The security attribute must have a value type. Security attribute can use either a static value or a list of possible values. Static values are entered by a user when applying the security attribute to a resource. Lists are created by the user and the user must apply a value from the list. Lists are validated.
 * 
 * ## Example Usage
 * 
 * &lt;!--Start PulumiCodeChooser --&gt;
 * <pre>
 * {@code
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.SecurityAttribute.SecurityAttribute;
 * import com.pulumi.oci.SecurityAttribute.SecurityAttributeArgs;
 * import com.pulumi.oci.SecurityAttribute.inputs.SecurityAttributeValidatorArgs;
 * import java.util.List;
 * import java.util.ArrayList;
 * import java.util.Map;
 * import java.io.File;
 * import java.nio.file.Files;
 * import java.nio.file.Paths;
 * 
 * public class App {
 *     public static void main(String[] args) {
 *         Pulumi.run(App::stack);
 *     }
 * 
 *     public static void stack(Context ctx) {
 *         var testSecurityAttribute = new SecurityAttribute("testSecurityAttribute", SecurityAttributeArgs.builder()
 *             .description(securityAttributeDescription)
 *             .name(securityAttributeName)
 *             .securityAttributeNamespaceId(testSecurityAttributeNamespace.id())
 *             .validator(SecurityAttributeValidatorArgs.builder()
 *                 .validatorType(securityAttributeValidatorValidatorType)
 *                 .values(securityAttributeValidatorValues)
 *                 .build())
 *             .build());
 * 
 *     }
 * }
 * }
 * </pre>
 * &lt;!--End PulumiCodeChooser --&gt;
 * 
 * ## Import
 * 
 * SecurityAttributes can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:SecurityAttribute/securityAttribute:SecurityAttribute test_security_attribute &#34;securityAttributeNamespaces/{securityAttributeNamespaceId}/securityAttributes/{securityAttributeName}&#34;
 * ```
 * 
 */
@ResourceType(type="oci:SecurityAttribute/securityAttribute:SecurityAttribute")
public class SecurityAttribute extends com.pulumi.resources.CustomResource {
    /**
     * The OCID of the compartment that contains the security attribute definition.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment that contains the security attribute definition.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) The description you assign to the security attribute during creation.
     * 
     */
    @Export(name="description", refs={String.class}, tree="[0]")
    private Output<String> description;

    /**
     * @return (Updatable) The description you assign to the security attribute during creation.
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * Indicates whether the security attribute is retired. See [Managing Security Attribute Namespaces](https://docs.cloud.oracle.com/iaas/Content/zero-trust-packet-routing/managing-security-attribute-namespaces.htm).
     * 
     */
    @Export(name="isRetired", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> isRetired;

    /**
     * @return Indicates whether the security attribute is retired. See [Managing Security Attribute Namespaces](https://docs.cloud.oracle.com/iaas/Content/zero-trust-packet-routing/managing-security-attribute-namespaces.htm).
     * 
     */
    public Output<Boolean> isRetired() {
        return this.isRetired;
    }
    /**
     * The name you assign to the security attribute during creation. This is the security attribute key. The name must be unique within the namespace and cannot be changed.
     * 
     */
    @Export(name="name", refs={String.class}, tree="[0]")
    private Output<String> name;

    /**
     * @return The name you assign to the security attribute during creation. This is the security attribute key. The name must be unique within the namespace and cannot be changed.
     * 
     */
    public Output<String> name() {
        return this.name;
    }
    /**
     * The OCID of the security attribute namespace.
     * 
     */
    @Export(name="securityAttributeNamespaceId", refs={String.class}, tree="[0]")
    private Output<String> securityAttributeNamespaceId;

    /**
     * @return The OCID of the security attribute namespace.
     * 
     */
    public Output<String> securityAttributeNamespaceId() {
        return this.securityAttributeNamespaceId;
    }
    /**
     * The name of the security attribute namespace that contains the security attribute.
     * 
     */
    @Export(name="securityAttributeNamespaceName", refs={String.class}, tree="[0]")
    private Output<String> securityAttributeNamespaceName;

    /**
     * @return The name of the security attribute namespace that contains the security attribute.
     * 
     */
    public Output<String> securityAttributeNamespaceName() {
        return this.securityAttributeNamespaceName;
    }
    /**
     * The security attribute&#39;s current state. After creating a security attribute, make sure its `lifecycleState` is ACTIVE before using it. After retiring a security attribute, make sure its `lifecycleState` is INACTIVE before using it. If you delete a security attribute, you cannot delete another security attribute until the deleted security attribute&#39;s `lifecycleState` changes from DELETING to DELETED.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The security attribute&#39;s current state. After creating a security attribute, make sure its `lifecycleState` is ACTIVE before using it. After retiring a security attribute, make sure its `lifecycleState` is INACTIVE before using it. If you delete a security attribute, you cannot delete another security attribute until the deleted security attribute&#39;s `lifecycleState` changes from DELETING to DELETED.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * Date and time the security attribute was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return Date and time the security attribute was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The data type of the security attribute.
     * 
     */
    @Export(name="type", refs={String.class}, tree="[0]")
    private Output<String> type;

    /**
     * @return The data type of the security attribute.
     * 
     */
    public Output<String> type() {
        return this.type;
    }
    /**
     * (Updatable) Validates a security attribute value. Each validator performs validation steps in addition to the standard validation for security attribute values. For more information, see [Limits on Security Attributes](https://docs.cloud.oracle.com/iaas/Content/zero-trust-packet-routing/overview.htm).
     * 
     * If you define a validator after a value has been set for a security attribute, then any updates that attempt to change the value must pass the additional validation defined by the current rule. Previously set values (even those that would fail the current validation) are not updated. You can still update other attributes to resources that contain a non-valid security attribute.
     * 
     * To clear the validator call UpdateSecurityAttribute with [DefaultSecuirtyAttributeValidator](https://docs.cloud.oracle.com/iaas/api/#/en/securityattribute/latest/datatypes/DefaultTagDefinitionValidator).
     * 
     */
    @Export(name="validator", refs={SecurityAttributeValidator.class}, tree="[0]")
    private Output</* @Nullable */ SecurityAttributeValidator> validator;

    /**
     * @return (Updatable) Validates a security attribute value. Each validator performs validation steps in addition to the standard validation for security attribute values. For more information, see [Limits on Security Attributes](https://docs.cloud.oracle.com/iaas/Content/zero-trust-packet-routing/overview.htm).
     * 
     * If you define a validator after a value has been set for a security attribute, then any updates that attempt to change the value must pass the additional validation defined by the current rule. Previously set values (even those that would fail the current validation) are not updated. You can still update other attributes to resources that contain a non-valid security attribute.
     * 
     * To clear the validator call UpdateSecurityAttribute with [DefaultSecuirtyAttributeValidator](https://docs.cloud.oracle.com/iaas/api/#/en/securityattribute/latest/datatypes/DefaultTagDefinitionValidator).
     * 
     */
    public Output<Optional<SecurityAttributeValidator>> validator() {
        return Codegen.optional(this.validator);
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public SecurityAttribute(java.lang.String name) {
        this(name, SecurityAttributeArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public SecurityAttribute(java.lang.String name, SecurityAttributeArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public SecurityAttribute(java.lang.String name, SecurityAttributeArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:SecurityAttribute/securityAttribute:SecurityAttribute", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private SecurityAttribute(java.lang.String name, Output<java.lang.String> id, @Nullable SecurityAttributeState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:SecurityAttribute/securityAttribute:SecurityAttribute", name, state, makeResourceOptions(options, id), false);
    }

    private static SecurityAttributeArgs makeArgs(SecurityAttributeArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? SecurityAttributeArgs.Empty : args;
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<java.lang.String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.CustomResourceOptions.merge(defaultOptions, options, id);
    }

    /**
     * Get an existing Host resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state
     * @param options Optional settings to control the behavior of the CustomResource.
     */
    public static SecurityAttribute get(java.lang.String name, Output<java.lang.String> id, @Nullable SecurityAttributeState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new SecurityAttribute(name, id, state, options);
    }
}
