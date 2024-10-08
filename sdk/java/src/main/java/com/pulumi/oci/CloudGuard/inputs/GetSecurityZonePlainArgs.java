// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetSecurityZonePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSecurityZonePlainArgs Empty = new GetSecurityZonePlainArgs();

    /**
     * The unique identifier of the security zone (`SecurityZone` resource).
     * 
     */
    @Import(name="securityZoneId", required=true)
    private String securityZoneId;

    /**
     * @return The unique identifier of the security zone (`SecurityZone` resource).
     * 
     */
    public String securityZoneId() {
        return this.securityZoneId;
    }

    private GetSecurityZonePlainArgs() {}

    private GetSecurityZonePlainArgs(GetSecurityZonePlainArgs $) {
        this.securityZoneId = $.securityZoneId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSecurityZonePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSecurityZonePlainArgs $;

        public Builder() {
            $ = new GetSecurityZonePlainArgs();
        }

        public Builder(GetSecurityZonePlainArgs defaults) {
            $ = new GetSecurityZonePlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param securityZoneId The unique identifier of the security zone (`SecurityZone` resource).
         * 
         * @return builder
         * 
         */
        public Builder securityZoneId(String securityZoneId) {
            $.securityZoneId = securityZoneId;
            return this;
        }

        public GetSecurityZonePlainArgs build() {
            if ($.securityZoneId == null) {
                throw new MissingRequiredPropertyException("GetSecurityZonePlainArgs", "securityZoneId");
            }
            return $;
        }
    }

}
