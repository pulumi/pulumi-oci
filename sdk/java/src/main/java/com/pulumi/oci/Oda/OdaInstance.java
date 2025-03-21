// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Oda;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Oda.OdaInstanceArgs;
import com.pulumi.oci.Oda.inputs.OdaInstanceState;
import com.pulumi.oci.Oda.outputs.OdaInstanceRestrictedOperation;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource provides the Oda Instance resource in Oracle Cloud Infrastructure Digital Assistant service.
 * 
 * Starts an asynchronous job to create a Digital Assistant instance.
 * 
 * To monitor the status of the job, take the `opc-work-request-id` response
 * header value and use it to call `GET /workRequests/{workRequestId}`.
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
 * import com.pulumi.oci.Oda.OdaInstance;
 * import com.pulumi.oci.Oda.OdaInstanceArgs;
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
 *         var testOdaInstance = new OdaInstance("testOdaInstance", OdaInstanceArgs.builder()
 *             .compartmentId(compartmentId)
 *             .shapeName("DEVELOPMENT")
 *             .definedTags(Map.of("foo-namespace.bar-key", "value"))
 *             .description(odaInstanceDescription)
 *             .displayName(odaInstanceDisplayName)
 *             .freeformTags(Map.of("bar-key", "value"))
 *             .identityDomain(odaInstanceIdentityDomain)
 *             .isRoleBasedAccess(odaInstanceIsRoleBasedAccess)
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
 * OdaInstances can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:Oda/odaInstance:OdaInstance test_oda_instance &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Oda/odaInstance:OdaInstance")
public class OdaInstance extends com.pulumi.resources.CustomResource {
    /**
     * A list of attachment identifiers for this instance (if any). Use GetOdaInstanceAttachment to get the details of the attachments.
     * 
     */
    @Export(name="attachmentIds", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> attachmentIds;

    /**
     * @return A list of attachment identifiers for this instance (if any). Use GetOdaInstanceAttachment to get the details of the attachments.
     * 
     */
    public Output<List<String>> attachmentIds() {
        return this.attachmentIds;
    }
    /**
     * A list of attachment types for this instance (if any). Use attachmentIds to get the details of the attachments.
     * 
     */
    @Export(name="attachmentTypes", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> attachmentTypes;

    /**
     * @return A list of attachment types for this instance (if any). Use attachmentIds to get the details of the attachments.
     * 
     */
    public Output<List<String>> attachmentTypes() {
        return this.attachmentTypes;
    }
    /**
     * (Updatable) Identifier of the compartment.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) Identifier of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * URL for the connector&#39;s endpoint.
     * 
     */
    @Export(name="connectorUrl", refs={String.class}, tree="[0]")
    private Output<String> connectorUrl;

    /**
     * @return URL for the connector&#39;s endpoint.
     * 
     */
    public Output<String> connectorUrl() {
        return this.connectorUrl;
    }
    /**
     * (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) Description of the Digital Assistant instance.
     * 
     */
    @Export(name="description", refs={String.class}, tree="[0]")
    private Output</* @Nullable */ String> description;

    /**
     * @return (Updatable) Description of the Digital Assistant instance.
     * 
     */
    public Output<Optional<String>> description() {
        return Codegen.optional(this.description);
    }
    /**
     * (Updatable) User-friendly name for the instance. Avoid entering confidential information. You can change this value anytime.
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return (Updatable) User-friendly name for the instance. Avoid entering confidential information. You can change this value anytime.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * If isRoleBasedAccess is set to true, this property specifies the URL for the administration console used to manage the Identity Application instance Digital Assistant has created inside the user-specified identity domain.
     * 
     */
    @Export(name="identityAppConsoleUrl", refs={String.class}, tree="[0]")
    private Output<String> identityAppConsoleUrl;

    /**
     * @return If isRoleBasedAccess is set to true, this property specifies the URL for the administration console used to manage the Identity Application instance Digital Assistant has created inside the user-specified identity domain.
     * 
     */
    public Output<String> identityAppConsoleUrl() {
        return this.identityAppConsoleUrl;
    }
    /**
     * If isRoleBasedAccess is set to true, this property specifies the GUID of the Identity Application instance Digital Assistant has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this Digital Assistant instance for users within the identity domain.
     * 
     */
    @Export(name="identityAppGuid", refs={String.class}, tree="[0]")
    private Output<String> identityAppGuid;

    /**
     * @return If isRoleBasedAccess is set to true, this property specifies the GUID of the Identity Application instance Digital Assistant has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this Digital Assistant instance for users within the identity domain.
     * 
     */
    public Output<String> identityAppGuid() {
        return this.identityAppGuid;
    }
    /**
     * If isRoleBasedAccess is set to true, this property specifies the identity domain that is to be used to implement this type of authorzation. Digital Assistant will create an Identity Application instance and Application Roles within this identity domain. The caller may then perform and user roll mappings they like to grant access to users within the identity domain.
     * 
     */
    @Export(name="identityDomain", refs={String.class}, tree="[0]")
    private Output<String> identityDomain;

    /**
     * @return If isRoleBasedAccess is set to true, this property specifies the identity domain that is to be used to implement this type of authorzation. Digital Assistant will create an Identity Application instance and Application Roles within this identity domain. The caller may then perform and user roll mappings they like to grant access to users within the identity domain.
     * 
     */
    public Output<String> identityDomain() {
        return this.identityDomain;
    }
    /**
     * A list of package ids imported into this instance (if any). Use GetImportedPackage to get the details of the imported packages.
     * 
     */
    @Export(name="importedPackageIds", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> importedPackageIds;

    /**
     * @return A list of package ids imported into this instance (if any). Use GetImportedPackage to get the details of the imported packages.
     * 
     */
    public Output<List<String>> importedPackageIds() {
        return this.importedPackageIds;
    }
    /**
     * A list of package names imported into this instance (if any). Use importedPackageIds field to get the details of the imported packages.
     * 
     */
    @Export(name="importedPackageNames", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> importedPackageNames;

    /**
     * @return A list of package names imported into this instance (if any). Use importedPackageIds field to get the details of the imported packages.
     * 
     */
    public Output<List<String>> importedPackageNames() {
        return this.importedPackageNames;
    }
    /**
     * Should this Digital Assistant instance use role-based authorization via an identity domain (true) or use the default policy-based authorization via IAM policies (false)
     * 
     */
    @Export(name="isRoleBasedAccess", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> isRoleBasedAccess;

    /**
     * @return Should this Digital Assistant instance use role-based authorization via an identity domain (true) or use the default policy-based authorization via IAM policies (false)
     * 
     */
    public Output<Boolean> isRoleBasedAccess() {
        return this.isRoleBasedAccess;
    }
    /**
     * The current sub-state of the Digital Assistant instance.
     * 
     */
    @Export(name="lifecycleSubState", refs={String.class}, tree="[0]")
    private Output<String> lifecycleSubState;

    /**
     * @return The current sub-state of the Digital Assistant instance.
     * 
     */
    public Output<String> lifecycleSubState() {
        return this.lifecycleSubState;
    }
    /**
     * A list of restricted operations (across all attachments) for this instance (if any). Use GetOdaInstanceAttachment to get the details of the attachments.
     * 
     */
    @Export(name="restrictedOperations", refs={List.class,OdaInstanceRestrictedOperation.class}, tree="[0,1]")
    private Output<List<OdaInstanceRestrictedOperation>> restrictedOperations;

    /**
     * @return A list of restricted operations (across all attachments) for this instance (if any). Use GetOdaInstanceAttachment to get the details of the attachments.
     * 
     */
    public Output<List<OdaInstanceRestrictedOperation>> restrictedOperations() {
        return this.restrictedOperations;
    }
    /**
     * Shape or size of the instance.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="shapeName", refs={String.class}, tree="[0]")
    private Output<String> shapeName;

    /**
     * @return Shape or size of the instance.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> shapeName() {
        return this.shapeName;
    }
    /**
     * The current state of the Digital Assistant instance.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of the Digital Assistant instance.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * A message that describes the current state in more detail. For example, actionable information about an instance that&#39;s in the `FAILED` state.
     * 
     */
    @Export(name="stateMessage", refs={String.class}, tree="[0]")
    private Output<String> stateMessage;

    /**
     * @return A message that describes the current state in more detail. For example, actionable information about an instance that&#39;s in the `FAILED` state.
     * 
     */
    public Output<String> stateMessage() {
        return this.stateMessage;
    }
    /**
     * When the Digital Assistant instance was created. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return When the Digital Assistant instance was created. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * When the Digital Assistance instance was last updated. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return When the Digital Assistance instance was last updated. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * URL for the Digital Assistant web application that&#39;s associated with the instance.
     * 
     */
    @Export(name="webAppUrl", refs={String.class}, tree="[0]")
    private Output<String> webAppUrl;

    /**
     * @return URL for the Digital Assistant web application that&#39;s associated with the instance.
     * 
     */
    public Output<String> webAppUrl() {
        return this.webAppUrl;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public OdaInstance(java.lang.String name) {
        this(name, OdaInstanceArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public OdaInstance(java.lang.String name, OdaInstanceArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public OdaInstance(java.lang.String name, OdaInstanceArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Oda/odaInstance:OdaInstance", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private OdaInstance(java.lang.String name, Output<java.lang.String> id, @Nullable OdaInstanceState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Oda/odaInstance:OdaInstance", name, state, makeResourceOptions(options, id), false);
    }

    private static OdaInstanceArgs makeArgs(OdaInstanceArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? OdaInstanceArgs.Empty : args;
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
    public static OdaInstance get(java.lang.String name, Output<java.lang.String> id, @Nullable OdaInstanceState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new OdaInstance(name, id, state, options);
    }
}
