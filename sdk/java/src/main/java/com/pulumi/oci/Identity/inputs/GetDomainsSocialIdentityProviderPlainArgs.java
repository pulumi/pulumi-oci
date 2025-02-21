// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDomainsSocialIdentityProviderPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDomainsSocialIdentityProviderPlainArgs Empty = new GetDomainsSocialIdentityProviderPlainArgs();

    /**
     * The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     * 
     */
    @Import(name="authorization")
    private @Nullable String authorization;

    /**
     * @return The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     * 
     */
    public Optional<String> authorization() {
        return Optional.ofNullable(this.authorization);
    }

    /**
     * The basic endpoint for the identity domain
     * 
     */
    @Import(name="idcsEndpoint", required=true)
    private String idcsEndpoint;

    /**
     * @return The basic endpoint for the identity domain
     * 
     */
    public String idcsEndpoint() {
        return this.idcsEndpoint;
    }

    /**
     * An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     * 
     */
    @Import(name="resourceTypeSchemaVersion")
    private @Nullable String resourceTypeSchemaVersion;

    /**
     * @return An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     * 
     */
    public Optional<String> resourceTypeSchemaVersion() {
        return Optional.ofNullable(this.resourceTypeSchemaVersion);
    }

    /**
     * ID of the resource
     * 
     */
    @Import(name="socialIdentityProviderId", required=true)
    private String socialIdentityProviderId;

    /**
     * @return ID of the resource
     * 
     */
    public String socialIdentityProviderId() {
        return this.socialIdentityProviderId;
    }

    private GetDomainsSocialIdentityProviderPlainArgs() {}

    private GetDomainsSocialIdentityProviderPlainArgs(GetDomainsSocialIdentityProviderPlainArgs $) {
        this.authorization = $.authorization;
        this.idcsEndpoint = $.idcsEndpoint;
        this.resourceTypeSchemaVersion = $.resourceTypeSchemaVersion;
        this.socialIdentityProviderId = $.socialIdentityProviderId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDomainsSocialIdentityProviderPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDomainsSocialIdentityProviderPlainArgs $;

        public Builder() {
            $ = new GetDomainsSocialIdentityProviderPlainArgs();
        }

        public Builder(GetDomainsSocialIdentityProviderPlainArgs defaults) {
            $ = new GetDomainsSocialIdentityProviderPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param authorization The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
         * 
         * @return builder
         * 
         */
        public Builder authorization(@Nullable String authorization) {
            $.authorization = authorization;
            return this;
        }

        /**
         * @param idcsEndpoint The basic endpoint for the identity domain
         * 
         * @return builder
         * 
         */
        public Builder idcsEndpoint(String idcsEndpoint) {
            $.idcsEndpoint = idcsEndpoint;
            return this;
        }

        /**
         * @param resourceTypeSchemaVersion An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
         * 
         * @return builder
         * 
         */
        public Builder resourceTypeSchemaVersion(@Nullable String resourceTypeSchemaVersion) {
            $.resourceTypeSchemaVersion = resourceTypeSchemaVersion;
            return this;
        }

        /**
         * @param socialIdentityProviderId ID of the resource
         * 
         * @return builder
         * 
         */
        public Builder socialIdentityProviderId(String socialIdentityProviderId) {
            $.socialIdentityProviderId = socialIdentityProviderId;
            return this;
        }

        public GetDomainsSocialIdentityProviderPlainArgs build() {
            if ($.idcsEndpoint == null) {
                throw new MissingRequiredPropertyException("GetDomainsSocialIdentityProviderPlainArgs", "idcsEndpoint");
            }
            if ($.socialIdentityProviderId == null) {
                throw new MissingRequiredPropertyException("GetDomainsSocialIdentityProviderPlainArgs", "socialIdentityProviderId");
            }
            return $;
        }
    }

}
