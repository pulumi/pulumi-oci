// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.oci.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetWlmsWlsDomainServerPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetWlmsWlsDomainServerPlainArgs Empty = new GetWlmsWlsDomainServerPlainArgs();

    /**
     * The unique identifier of a server.
     * 
     * **Note:** Not an [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="serverId", required=true)
    private String serverId;

    /**
     * @return The unique identifier of a server.
     * 
     * **Note:** Not an [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String serverId() {
        return this.serverId;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebLogic domain.
     * 
     */
    @Import(name="wlsDomainId", required=true)
    private String wlsDomainId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebLogic domain.
     * 
     */
    public String wlsDomainId() {
        return this.wlsDomainId;
    }

    private GetWlmsWlsDomainServerPlainArgs() {}

    private GetWlmsWlsDomainServerPlainArgs(GetWlmsWlsDomainServerPlainArgs $) {
        this.serverId = $.serverId;
        this.wlsDomainId = $.wlsDomainId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetWlmsWlsDomainServerPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetWlmsWlsDomainServerPlainArgs $;

        public Builder() {
            $ = new GetWlmsWlsDomainServerPlainArgs();
        }

        public Builder(GetWlmsWlsDomainServerPlainArgs defaults) {
            $ = new GetWlmsWlsDomainServerPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param serverId The unique identifier of a server.
         * 
         * **Note:** Not an [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder serverId(String serverId) {
            $.serverId = serverId;
            return this;
        }

        /**
         * @param wlsDomainId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebLogic domain.
         * 
         * @return builder
         * 
         */
        public Builder wlsDomainId(String wlsDomainId) {
            $.wlsDomainId = wlsDomainId;
            return this;
        }

        public GetWlmsWlsDomainServerPlainArgs build() {
            if ($.serverId == null) {
                throw new MissingRequiredPropertyException("GetWlmsWlsDomainServerPlainArgs", "serverId");
            }
            if ($.wlsDomainId == null) {
                throw new MissingRequiredPropertyException("GetWlmsWlsDomainServerPlainArgs", "wlsDomainId");
            }
            return $;
        }
    }

}
