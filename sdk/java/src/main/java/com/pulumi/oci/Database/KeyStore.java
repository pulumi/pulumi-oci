// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Database.KeyStoreArgs;
import com.pulumi.oci.Database.inputs.KeyStoreState;
import com.pulumi.oci.Database.outputs.KeyStoreAssociatedDatabase;
import com.pulumi.oci.Database.outputs.KeyStoreTypeDetails;
import com.pulumi.oci.Utilities;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Key Store resource in Oracle Cloud Infrastructure Database service.
 * 
 * Creates a Key Store.
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.Database.KeyStore;
 * import com.pulumi.oci.Database.KeyStoreArgs;
 * import com.pulumi.oci.Database.inputs.KeyStoreTypeDetailsArgs;
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
 *         var testKeyStore = new KeyStore(&#34;testKeyStore&#34;, KeyStoreArgs.builder()        
 *             .compartmentId(var_.compartment_id())
 *             .displayName(var_.key_store_display_name())
 *             .typeDetails(KeyStoreTypeDetailsArgs.builder()
 *                 .adminUsername(var_.key_store_type_details_admin_username())
 *                 .connectionIps(var_.key_store_type_details_connection_ips())
 *                 .secretId(oci_vault_secret.test_secret().id())
 *                 .type(var_.key_store_type_details_type())
 *                 .vaultId(oci_kms_vault.test_vault().id())
 *                 .build())
 *             .definedTags(var_.key_store_defined_tags())
 *             .freeformTags(Map.of(&#34;Department&#34;, &#34;Finance&#34;))
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * KeyStores can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Database/keyStore:KeyStore test_key_store &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Database/keyStore:KeyStore")
public class KeyStore extends com.pulumi.resources.CustomResource {
    /**
     * List of databases associated with the key store.
     * 
     */
    @Export(name="associatedDatabases", type=List.class, parameters={KeyStoreAssociatedDatabase.class})
    private Output<List<KeyStoreAssociatedDatabase>> associatedDatabases;

    /**
     * @return List of databases associated with the key store.
     * 
     */
    public Output<List<KeyStoreAssociatedDatabase>> associatedDatabases() {
        return this.associatedDatabases;
    }
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    @Export(name="definedTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * The user-friendly name for the key store. The name does not need to be unique.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return The user-friendly name for the key store. The name does not need to be unique.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * Additional information about the current lifecycle state.
     * 
     */
    @Export(name="lifecycleDetails", type=String.class, parameters={})
    private Output<String> lifecycleDetails;

    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * The current state of the key store.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the key store.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The date and time that the key store was created.
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The date and time that the key store was created.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * (Updatable) Key store type details.
     * 
     */
    @Export(name="typeDetails", type=KeyStoreTypeDetails.class, parameters={})
    private Output<KeyStoreTypeDetails> typeDetails;

    /**
     * @return (Updatable) Key store type details.
     * 
     */
    public Output<KeyStoreTypeDetails> typeDetails() {
        return this.typeDetails;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public KeyStore(String name) {
        this(name, KeyStoreArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public KeyStore(String name, KeyStoreArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public KeyStore(String name, KeyStoreArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Database/keyStore:KeyStore", name, args == null ? KeyStoreArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private KeyStore(String name, Output<String> id, @Nullable KeyStoreState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Database/keyStore:KeyStore", name, state, makeResourceOptions(options, id));
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<String> id) {
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
    public static KeyStore get(String name, Output<String> id, @Nullable KeyStoreState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new KeyStore(name, id, state, options);
    }
}