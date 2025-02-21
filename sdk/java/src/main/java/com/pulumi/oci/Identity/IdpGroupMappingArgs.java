// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class IdpGroupMappingArgs extends com.pulumi.resources.ResourceArgs {

    public static final IdpGroupMappingArgs Empty = new IdpGroupMappingArgs();

    /**
     * (Updatable) The OCID of the IAM Service [group](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/Group/) you want to map to the IdP group.
     * 
     */
    @Import(name="groupId", required=true)
    private Output<String> groupId;

    /**
     * @return (Updatable) The OCID of the IAM Service [group](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/Group/) you want to map to the IdP group.
     * 
     */
    public Output<String> groupId() {
        return this.groupId;
    }

    /**
     * The OCID of the identity provider.
     * 
     */
    @Import(name="identityProviderId", required=true)
    private Output<String> identityProviderId;

    /**
     * @return The OCID of the identity provider.
     * 
     */
    public Output<String> identityProviderId() {
        return this.identityProviderId;
    }

    /**
     * (Updatable) The name of the IdP group you want to map.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="idpGroupName", required=true)
    private Output<String> idpGroupName;

    /**
     * @return (Updatable) The name of the IdP group you want to map.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> idpGroupName() {
        return this.idpGroupName;
    }

    private IdpGroupMappingArgs() {}

    private IdpGroupMappingArgs(IdpGroupMappingArgs $) {
        this.groupId = $.groupId;
        this.identityProviderId = $.identityProviderId;
        this.idpGroupName = $.idpGroupName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(IdpGroupMappingArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private IdpGroupMappingArgs $;

        public Builder() {
            $ = new IdpGroupMappingArgs();
        }

        public Builder(IdpGroupMappingArgs defaults) {
            $ = new IdpGroupMappingArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param groupId (Updatable) The OCID of the IAM Service [group](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/Group/) you want to map to the IdP group.
         * 
         * @return builder
         * 
         */
        public Builder groupId(Output<String> groupId) {
            $.groupId = groupId;
            return this;
        }

        /**
         * @param groupId (Updatable) The OCID of the IAM Service [group](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/Group/) you want to map to the IdP group.
         * 
         * @return builder
         * 
         */
        public Builder groupId(String groupId) {
            return groupId(Output.of(groupId));
        }

        /**
         * @param identityProviderId The OCID of the identity provider.
         * 
         * @return builder
         * 
         */
        public Builder identityProviderId(Output<String> identityProviderId) {
            $.identityProviderId = identityProviderId;
            return this;
        }

        /**
         * @param identityProviderId The OCID of the identity provider.
         * 
         * @return builder
         * 
         */
        public Builder identityProviderId(String identityProviderId) {
            return identityProviderId(Output.of(identityProviderId));
        }

        /**
         * @param idpGroupName (Updatable) The name of the IdP group you want to map.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder idpGroupName(Output<String> idpGroupName) {
            $.idpGroupName = idpGroupName;
            return this;
        }

        /**
         * @param idpGroupName (Updatable) The name of the IdP group you want to map.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder idpGroupName(String idpGroupName) {
            return idpGroupName(Output.of(idpGroupName));
        }

        public IdpGroupMappingArgs build() {
            if ($.groupId == null) {
                throw new MissingRequiredPropertyException("IdpGroupMappingArgs", "groupId");
            }
            if ($.identityProviderId == null) {
                throw new MissingRequiredPropertyException("IdpGroupMappingArgs", "identityProviderId");
            }
            if ($.idpGroupName == null) {
                throw new MissingRequiredPropertyException("IdpGroupMappingArgs", "idpGroupName");
            }
            return $;
        }
    }

}
