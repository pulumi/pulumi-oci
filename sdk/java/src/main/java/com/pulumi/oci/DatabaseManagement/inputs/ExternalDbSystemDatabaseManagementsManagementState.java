// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ExternalDbSystemDatabaseManagementsManagementState extends com.pulumi.resources.ResourceArgs {

    public static final ExternalDbSystemDatabaseManagementsManagementState Empty = new ExternalDbSystemDatabaseManagementsManagementState();

    /**
     * (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="enableDatabaseManagement")
    private @Nullable Output<Boolean> enableDatabaseManagement;

    /**
     * @return (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<Boolean>> enableDatabaseManagement() {
        return Optional.ofNullable(this.enableDatabaseManagement);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
     * 
     */
    @Import(name="externalDbSystemId")
    private @Nullable Output<String> externalDbSystemId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
     * 
     */
    public Optional<Output<String>> externalDbSystemId() {
        return Optional.ofNullable(this.externalDbSystemId);
    }

    /**
     * The Oracle license model that applies to the external database.
     * 
     */
    @Import(name="licenseModel")
    private @Nullable Output<String> licenseModel;

    /**
     * @return The Oracle license model that applies to the external database.
     * 
     */
    public Optional<Output<String>> licenseModel() {
        return Optional.ofNullable(this.licenseModel);
    }

    private ExternalDbSystemDatabaseManagementsManagementState() {}

    private ExternalDbSystemDatabaseManagementsManagementState(ExternalDbSystemDatabaseManagementsManagementState $) {
        this.enableDatabaseManagement = $.enableDatabaseManagement;
        this.externalDbSystemId = $.externalDbSystemId;
        this.licenseModel = $.licenseModel;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ExternalDbSystemDatabaseManagementsManagementState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ExternalDbSystemDatabaseManagementsManagementState $;

        public Builder() {
            $ = new ExternalDbSystemDatabaseManagementsManagementState();
        }

        public Builder(ExternalDbSystemDatabaseManagementsManagementState defaults) {
            $ = new ExternalDbSystemDatabaseManagementsManagementState(Objects.requireNonNull(defaults));
        }

        /**
         * @param enableDatabaseManagement (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder enableDatabaseManagement(@Nullable Output<Boolean> enableDatabaseManagement) {
            $.enableDatabaseManagement = enableDatabaseManagement;
            return this;
        }

        /**
         * @param enableDatabaseManagement (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder enableDatabaseManagement(Boolean enableDatabaseManagement) {
            return enableDatabaseManagement(Output.of(enableDatabaseManagement));
        }

        /**
         * @param externalDbSystemId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
         * 
         * @return builder
         * 
         */
        public Builder externalDbSystemId(@Nullable Output<String> externalDbSystemId) {
            $.externalDbSystemId = externalDbSystemId;
            return this;
        }

        /**
         * @param externalDbSystemId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
         * 
         * @return builder
         * 
         */
        public Builder externalDbSystemId(String externalDbSystemId) {
            return externalDbSystemId(Output.of(externalDbSystemId));
        }

        /**
         * @param licenseModel The Oracle license model that applies to the external database.
         * 
         * @return builder
         * 
         */
        public Builder licenseModel(@Nullable Output<String> licenseModel) {
            $.licenseModel = licenseModel;
            return this;
        }

        /**
         * @param licenseModel The Oracle license model that applies to the external database.
         * 
         * @return builder
         * 
         */
        public Builder licenseModel(String licenseModel) {
            return licenseModel(Output.of(licenseModel));
        }

        public ExternalDbSystemDatabaseManagementsManagementState build() {
            return $;
        }
    }

}
