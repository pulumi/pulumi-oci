// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class CloudExadataInfrastructureCustomerContactArgs extends com.pulumi.resources.ResourceArgs {

    public static final CloudExadataInfrastructureCustomerContactArgs Empty = new CloudExadataInfrastructureCustomerContactArgs();

    /**
     * (Updatable) The email address used by Oracle to send notifications regarding databases and infrastructure.
     * 
     */
    @Import(name="email")
    private @Nullable Output<String> email;

    /**
     * @return (Updatable) The email address used by Oracle to send notifications regarding databases and infrastructure.
     * 
     */
    public Optional<Output<String>> email() {
        return Optional.ofNullable(this.email);
    }

    private CloudExadataInfrastructureCustomerContactArgs() {}

    private CloudExadataInfrastructureCustomerContactArgs(CloudExadataInfrastructureCustomerContactArgs $) {
        this.email = $.email;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(CloudExadataInfrastructureCustomerContactArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private CloudExadataInfrastructureCustomerContactArgs $;

        public Builder() {
            $ = new CloudExadataInfrastructureCustomerContactArgs();
        }

        public Builder(CloudExadataInfrastructureCustomerContactArgs defaults) {
            $ = new CloudExadataInfrastructureCustomerContactArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param email (Updatable) The email address used by Oracle to send notifications regarding databases and infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder email(@Nullable Output<String> email) {
            $.email = email;
            return this;
        }

        /**
         * @param email (Updatable) The email address used by Oracle to send notifications regarding databases and infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder email(String email) {
            return email(Output.of(email));
        }

        public CloudExadataInfrastructureCustomerContactArgs build() {
            return $;
        }
    }

}