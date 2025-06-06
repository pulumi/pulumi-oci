// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataScience.inputs.MlApplicationImplementationLoggingArgs;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MlApplicationImplementationArgs extends com.pulumi.resources.ResourceArgs {

    public static final MlApplicationImplementationArgs Empty = new MlApplicationImplementationArgs();

    /**
     * (Updatable) List of ML Application Implementation OCIDs for which migration from this implementation is allowed. Migration means that if consumers change implementation for their instances to implementation with OCID from this list, instance components will be updated in place otherwise new instance components are created based on the new implementation and old instance components are removed.
     * 
     */
    @Import(name="allowedMigrationDestinations")
    private @Nullable Output<List<String>> allowedMigrationDestinations;

    /**
     * @return (Updatable) List of ML Application Implementation OCIDs for which migration from this implementation is allowed. Migration means that if consumers change implementation for their instances to implementation with OCID from this list, instance components will be updated in place otherwise new instance components are created based on the new implementation and old instance components are removed.
     * 
     */
    public Optional<Output<List<String>>> allowedMigrationDestinations() {
        return Optional.ofNullable(this.allowedMigrationDestinations);
    }

    /**
     * (Updatable) The OCID of the compartment where ML Application Implementation is created.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment where ML Application Implementation is created.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) Configuration of Logging for ML Application Implementation.
     * 
     */
    @Import(name="logging")
    private @Nullable Output<MlApplicationImplementationLoggingArgs> logging;

    /**
     * @return (Updatable) Configuration of Logging for ML Application Implementation.
     * 
     */
    public Optional<Output<MlApplicationImplementationLoggingArgs>> logging() {
        return Optional.ofNullable(this.logging);
    }

    /**
     * The OCID of the ML Application implemented by this ML Application Implementation
     * 
     */
    @Import(name="mlApplicationId", required=true)
    private Output<String> mlApplicationId;

    /**
     * @return The OCID of the ML Application implemented by this ML Application Implementation
     * 
     */
    public Output<String> mlApplicationId() {
        return this.mlApplicationId;
    }

    /**
     * (Updatable) Configuration of The ML Application Package to upload.
     * 
     */
    @Import(name="mlApplicationPackage")
    private @Nullable Output<Map<String,String>> mlApplicationPackage;

    /**
     * @return (Updatable) Configuration of The ML Application Package to upload.
     * 
     */
    public Optional<Output<Map<String,String>>> mlApplicationPackage() {
        return Optional.ofNullable(this.mlApplicationPackage);
    }

    /**
     * ML Application Implementation name which is unique for given ML Application.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return ML Application Implementation name which is unique for given ML Application.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * (Updatable) ML Application package arguments required during ML Application package upload. Each argument is a simple key-value pair.
     * 
     */
    @Import(name="opcMlAppPackageArgs")
    private @Nullable Output<Map<String,String>> opcMlAppPackageArgs;

    /**
     * @return (Updatable) ML Application package arguments required during ML Application package upload. Each argument is a simple key-value pair.
     * 
     */
    public Optional<Output<Map<String,String>>> opcMlAppPackageArgs() {
        return Optional.ofNullable(this.opcMlAppPackageArgs);
    }

    private MlApplicationImplementationArgs() {}

    private MlApplicationImplementationArgs(MlApplicationImplementationArgs $) {
        this.allowedMigrationDestinations = $.allowedMigrationDestinations;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.freeformTags = $.freeformTags;
        this.logging = $.logging;
        this.mlApplicationId = $.mlApplicationId;
        this.mlApplicationPackage = $.mlApplicationPackage;
        this.name = $.name;
        this.opcMlAppPackageArgs = $.opcMlAppPackageArgs;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MlApplicationImplementationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MlApplicationImplementationArgs $;

        public Builder() {
            $ = new MlApplicationImplementationArgs();
        }

        public Builder(MlApplicationImplementationArgs defaults) {
            $ = new MlApplicationImplementationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param allowedMigrationDestinations (Updatable) List of ML Application Implementation OCIDs for which migration from this implementation is allowed. Migration means that if consumers change implementation for their instances to implementation with OCID from this list, instance components will be updated in place otherwise new instance components are created based on the new implementation and old instance components are removed.
         * 
         * @return builder
         * 
         */
        public Builder allowedMigrationDestinations(@Nullable Output<List<String>> allowedMigrationDestinations) {
            $.allowedMigrationDestinations = allowedMigrationDestinations;
            return this;
        }

        /**
         * @param allowedMigrationDestinations (Updatable) List of ML Application Implementation OCIDs for which migration from this implementation is allowed. Migration means that if consumers change implementation for their instances to implementation with OCID from this list, instance components will be updated in place otherwise new instance components are created based on the new implementation and old instance components are removed.
         * 
         * @return builder
         * 
         */
        public Builder allowedMigrationDestinations(List<String> allowedMigrationDestinations) {
            return allowedMigrationDestinations(Output.of(allowedMigrationDestinations));
        }

        /**
         * @param allowedMigrationDestinations (Updatable) List of ML Application Implementation OCIDs for which migration from this implementation is allowed. Migration means that if consumers change implementation for their instances to implementation with OCID from this list, instance components will be updated in place otherwise new instance components are created based on the new implementation and old instance components are removed.
         * 
         * @return builder
         * 
         */
        public Builder allowedMigrationDestinations(String... allowedMigrationDestinations) {
            return allowedMigrationDestinations(List.of(allowedMigrationDestinations));
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment where ML Application Implementation is created.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment where ML Application Implementation is created.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param logging (Updatable) Configuration of Logging for ML Application Implementation.
         * 
         * @return builder
         * 
         */
        public Builder logging(@Nullable Output<MlApplicationImplementationLoggingArgs> logging) {
            $.logging = logging;
            return this;
        }

        /**
         * @param logging (Updatable) Configuration of Logging for ML Application Implementation.
         * 
         * @return builder
         * 
         */
        public Builder logging(MlApplicationImplementationLoggingArgs logging) {
            return logging(Output.of(logging));
        }

        /**
         * @param mlApplicationId The OCID of the ML Application implemented by this ML Application Implementation
         * 
         * @return builder
         * 
         */
        public Builder mlApplicationId(Output<String> mlApplicationId) {
            $.mlApplicationId = mlApplicationId;
            return this;
        }

        /**
         * @param mlApplicationId The OCID of the ML Application implemented by this ML Application Implementation
         * 
         * @return builder
         * 
         */
        public Builder mlApplicationId(String mlApplicationId) {
            return mlApplicationId(Output.of(mlApplicationId));
        }

        /**
         * @param mlApplicationPackage (Updatable) Configuration of The ML Application Package to upload.
         * 
         * @return builder
         * 
         */
        public Builder mlApplicationPackage(@Nullable Output<Map<String,String>> mlApplicationPackage) {
            $.mlApplicationPackage = mlApplicationPackage;
            return this;
        }

        /**
         * @param mlApplicationPackage (Updatable) Configuration of The ML Application Package to upload.
         * 
         * @return builder
         * 
         */
        public Builder mlApplicationPackage(Map<String,String> mlApplicationPackage) {
            return mlApplicationPackage(Output.of(mlApplicationPackage));
        }

        /**
         * @param name ML Application Implementation name which is unique for given ML Application.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name ML Application Implementation name which is unique for given ML Application.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param opcMlAppPackageArgs (Updatable) ML Application package arguments required during ML Application package upload. Each argument is a simple key-value pair.
         * 
         * @return builder
         * 
         */
        public Builder opcMlAppPackageArgs(@Nullable Output<Map<String,String>> opcMlAppPackageArgs) {
            $.opcMlAppPackageArgs = opcMlAppPackageArgs;
            return this;
        }

        /**
         * @param opcMlAppPackageArgs (Updatable) ML Application package arguments required during ML Application package upload. Each argument is a simple key-value pair.
         * 
         * @return builder
         * 
         */
        public Builder opcMlAppPackageArgs(Map<String,String> opcMlAppPackageArgs) {
            return opcMlAppPackageArgs(Output.of(opcMlAppPackageArgs));
        }

        public MlApplicationImplementationArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("MlApplicationImplementationArgs", "compartmentId");
            }
            if ($.mlApplicationId == null) {
                throw new MissingRequiredPropertyException("MlApplicationImplementationArgs", "mlApplicationId");
            }
            return $;
        }
    }

}
