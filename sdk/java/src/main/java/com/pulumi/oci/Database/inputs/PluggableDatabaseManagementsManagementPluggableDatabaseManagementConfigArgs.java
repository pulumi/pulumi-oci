// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class PluggableDatabaseManagementsManagementPluggableDatabaseManagementConfigArgs extends com.pulumi.resources.ResourceArgs {

    public static final PluggableDatabaseManagementsManagementPluggableDatabaseManagementConfigArgs Empty = new PluggableDatabaseManagementsManagementPluggableDatabaseManagementConfigArgs();

    /**
     * (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="enablePluggabledatabasemanagement", required=true)
    private Output<Boolean> enablePluggabledatabasemanagement;

    /**
     * @return (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<Boolean> enablePluggabledatabasemanagement() {
        return this.enablePluggabledatabasemanagement;
    }

    /**
     * The status of the Pluggable Database Management service.
     * 
     */
    @Import(name="managementStatus")
    private @Nullable Output<String> managementStatus;

    /**
     * @return The status of the Pluggable Database Management service.
     * 
     */
    public Optional<Output<String>> managementStatus() {
        return Optional.ofNullable(this.managementStatus);
    }

    private PluggableDatabaseManagementsManagementPluggableDatabaseManagementConfigArgs() {}

    private PluggableDatabaseManagementsManagementPluggableDatabaseManagementConfigArgs(PluggableDatabaseManagementsManagementPluggableDatabaseManagementConfigArgs $) {
        this.enablePluggabledatabasemanagement = $.enablePluggabledatabasemanagement;
        this.managementStatus = $.managementStatus;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(PluggableDatabaseManagementsManagementPluggableDatabaseManagementConfigArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private PluggableDatabaseManagementsManagementPluggableDatabaseManagementConfigArgs $;

        public Builder() {
            $ = new PluggableDatabaseManagementsManagementPluggableDatabaseManagementConfigArgs();
        }

        public Builder(PluggableDatabaseManagementsManagementPluggableDatabaseManagementConfigArgs defaults) {
            $ = new PluggableDatabaseManagementsManagementPluggableDatabaseManagementConfigArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param enablePluggabledatabasemanagement (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder enablePluggabledatabasemanagement(Output<Boolean> enablePluggabledatabasemanagement) {
            $.enablePluggabledatabasemanagement = enablePluggabledatabasemanagement;
            return this;
        }

        /**
         * @param enablePluggabledatabasemanagement (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder enablePluggabledatabasemanagement(Boolean enablePluggabledatabasemanagement) {
            return enablePluggabledatabasemanagement(Output.of(enablePluggabledatabasemanagement));
        }

        /**
         * @param managementStatus The status of the Pluggable Database Management service.
         * 
         * @return builder
         * 
         */
        public Builder managementStatus(@Nullable Output<String> managementStatus) {
            $.managementStatus = managementStatus;
            return this;
        }

        /**
         * @param managementStatus The status of the Pluggable Database Management service.
         * 
         * @return builder
         * 
         */
        public Builder managementStatus(String managementStatus) {
            return managementStatus(Output.of(managementStatus));
        }

        public PluggableDatabaseManagementsManagementPluggableDatabaseManagementConfigArgs build() {
            if ($.enablePluggabledatabasemanagement == null) {
                throw new MissingRequiredPropertyException("PluggableDatabaseManagementsManagementPluggableDatabaseManagementConfigArgs", "enablePluggabledatabasemanagement");
            }
            return $;
        }
    }

}
