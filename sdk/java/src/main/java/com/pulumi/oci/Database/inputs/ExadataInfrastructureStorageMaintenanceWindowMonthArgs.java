// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class ExadataInfrastructureStorageMaintenanceWindowMonthArgs extends com.pulumi.resources.ResourceArgs {

    public static final ExadataInfrastructureStorageMaintenanceWindowMonthArgs Empty = new ExadataInfrastructureStorageMaintenanceWindowMonthArgs();

    @Import(name="name", required=true)
    private Output<String> name;

    public Output<String> name() {
        return this.name;
    }

    private ExadataInfrastructureStorageMaintenanceWindowMonthArgs() {}

    private ExadataInfrastructureStorageMaintenanceWindowMonthArgs(ExadataInfrastructureStorageMaintenanceWindowMonthArgs $) {
        this.name = $.name;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ExadataInfrastructureStorageMaintenanceWindowMonthArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ExadataInfrastructureStorageMaintenanceWindowMonthArgs $;

        public Builder() {
            $ = new ExadataInfrastructureStorageMaintenanceWindowMonthArgs();
        }

        public Builder(ExadataInfrastructureStorageMaintenanceWindowMonthArgs defaults) {
            $ = new ExadataInfrastructureStorageMaintenanceWindowMonthArgs(Objects.requireNonNull(defaults));
        }

        public Builder name(Output<String> name) {
            $.name = name;
            return this;
        }

        public Builder name(String name) {
            return name(Output.of(name));
        }

        public ExadataInfrastructureStorageMaintenanceWindowMonthArgs build() {
            if ($.name == null) {
                throw new MissingRequiredPropertyException("ExadataInfrastructureStorageMaintenanceWindowMonthArgs", "name");
            }
            return $;
        }
    }

}
