// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.BigDataService.BdsInstanceApiKeyArgs;
import com.pulumi.oci.BigDataService.inputs.BdsInstanceApiKeyState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import javax.annotation.Nullable;

/**
 * This resource provides the Bds Instance Api Key resource in Oracle Cloud Infrastructure Big Data Service service.
 * 
 * Create an API key on behalf of the specified user.
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
 * import com.pulumi.oci.BigDataService.BdsInstanceApiKey;
 * import com.pulumi.oci.BigDataService.BdsInstanceApiKeyArgs;
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
 *         var testBdsInstanceApiKey = new BdsInstanceApiKey("testBdsInstanceApiKey", BdsInstanceApiKeyArgs.builder()
 *             .bdsInstanceId(testBdsInstance.id())
 *             .keyAlias(bdsInstanceApiKeyKeyAlias)
 *             .passphrase(bdsInstanceApiKeyPassphrase)
 *             .userId(testUser.id())
 *             .defaultRegion(bdsInstanceApiKeyDefaultRegion)
 *             .domainOcid(bdsInstanceApiKeyDomainOcid)
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
 * BdsInstanceApiKeys can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:BigDataService/bdsInstanceApiKey:BdsInstanceApiKey test_bds_instance_api_key &#34;bdsInstances/{bdsInstanceId}/apiKeys/{apiKeyId}&#34;
 * ```
 * 
 */
@ResourceType(type="oci:BigDataService/bdsInstanceApiKey:BdsInstanceApiKey")
public class BdsInstanceApiKey extends com.pulumi.resources.CustomResource {
    /**
     * The OCID of the cluster.
     * 
     */
    @Export(name="bdsInstanceId", refs={String.class}, tree="[0]")
    private Output<String> bdsInstanceId;

    /**
     * @return The OCID of the cluster.
     * 
     */
    public Output<String> bdsInstanceId() {
        return this.bdsInstanceId;
    }
    /**
     * The name of the region to establish the Object Storage endpoint. See https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/Region/ for additional information.
     * 
     */
    @Export(name="defaultRegion", refs={String.class}, tree="[0]")
    private Output<String> defaultRegion;

    /**
     * @return The name of the region to establish the Object Storage endpoint. See https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/Region/ for additional information.
     * 
     */
    public Output<String> defaultRegion() {
        return this.defaultRegion;
    }
    /**
     * Identity domain OCID , where user is present. For default domain , this field will be optional.
     * 
     */
    @Export(name="domainOcid", refs={String.class}, tree="[0]")
    private Output<String> domainOcid;

    /**
     * @return Identity domain OCID , where user is present. For default domain , this field will be optional.
     * 
     */
    public Output<String> domainOcid() {
        return this.domainOcid;
    }
    /**
     * The fingerprint that corresponds to the public API key requested.
     * 
     */
    @Export(name="fingerprint", refs={String.class}, tree="[0]")
    private Output<String> fingerprint;

    /**
     * @return The fingerprint that corresponds to the public API key requested.
     * 
     */
    public Output<String> fingerprint() {
        return this.fingerprint;
    }
    /**
     * User friendly identifier used to uniquely differentiate between different API keys associated with this Big Data Service cluster. Only ASCII alphanumeric characters with no spaces allowed.
     * 
     */
    @Export(name="keyAlias", refs={String.class}, tree="[0]")
    private Output<String> keyAlias;

    /**
     * @return User friendly identifier used to uniquely differentiate between different API keys associated with this Big Data Service cluster. Only ASCII alphanumeric characters with no spaces allowed.
     * 
     */
    public Output<String> keyAlias() {
        return this.keyAlias;
    }
    /**
     * Base64 passphrase used to secure the private key which will be created on user behalf.
     * 
     */
    @Export(name="passphrase", refs={String.class}, tree="[0]")
    private Output<String> passphrase;

    /**
     * @return Base64 passphrase used to secure the private key which will be created on user behalf.
     * 
     */
    public Output<String> passphrase() {
        return this.passphrase;
    }
    /**
     * The full path and file name of the private key used for authentication. This location will be automatically selected on the BDS local file system.
     * 
     */
    @Export(name="pemfilepath", refs={String.class}, tree="[0]")
    private Output<String> pemfilepath;

    /**
     * @return The full path and file name of the private key used for authentication. This location will be automatically selected on the BDS local file system.
     * 
     */
    public Output<String> pemfilepath() {
        return this.pemfilepath;
    }
    /**
     * The current status of the API key.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current status of the API key.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The OCID of your tenancy.
     * 
     */
    @Export(name="tenantId", refs={String.class}, tree="[0]")
    private Output<String> tenantId;

    /**
     * @return The OCID of your tenancy.
     * 
     */
    public Output<String> tenantId() {
        return this.tenantId;
    }
    /**
     * The time the API key was created, shown as an RFC 3339 formatted datetime string.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The time the API key was created, shown as an RFC 3339 formatted datetime string.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The OCID of the user for whom this new generated API key pair will be created.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="userId", refs={String.class}, tree="[0]")
    private Output<String> userId;

    /**
     * @return The OCID of the user for whom this new generated API key pair will be created.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> userId() {
        return this.userId;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public BdsInstanceApiKey(java.lang.String name) {
        this(name, BdsInstanceApiKeyArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public BdsInstanceApiKey(java.lang.String name, BdsInstanceApiKeyArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public BdsInstanceApiKey(java.lang.String name, BdsInstanceApiKeyArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:BigDataService/bdsInstanceApiKey:BdsInstanceApiKey", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private BdsInstanceApiKey(java.lang.String name, Output<java.lang.String> id, @Nullable BdsInstanceApiKeyState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:BigDataService/bdsInstanceApiKey:BdsInstanceApiKey", name, state, makeResourceOptions(options, id), false);
    }

    private static BdsInstanceApiKeyArgs makeArgs(BdsInstanceApiKeyArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? BdsInstanceApiKeyArgs.Empty : args;
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<java.lang.String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .additionalSecretOutputs(List.of(
                "passphrase"
            ))
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
    public static BdsInstanceApiKey get(java.lang.String name, Output<java.lang.String> id, @Nullable BdsInstanceApiKeyState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new BdsInstanceApiKey(name, id, state, options);
    }
}
