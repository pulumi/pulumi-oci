// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Integration.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class IntegrationInstanceIdcsInfoArgs extends com.pulumi.resources.ResourceArgs {

    public static final IntegrationInstanceIdcsInfoArgs Empty = new IntegrationInstanceIdcsInfoArgs();

    /**
     * The IDCS application display name associated with the instance
     * 
     */
    @Import(name="idcsAppDisplayName")
    private @Nullable Output<String> idcsAppDisplayName;

    /**
     * @return The IDCS application display name associated with the instance
     * 
     */
    public Optional<Output<String>> idcsAppDisplayName() {
        return Optional.ofNullable(this.idcsAppDisplayName);
    }

    /**
     * The IDCS application ID associated with the instance
     * 
     */
    @Import(name="idcsAppId")
    private @Nullable Output<String> idcsAppId;

    /**
     * @return The IDCS application ID associated with the instance
     * 
     */
    public Optional<Output<String>> idcsAppId() {
        return Optional.ofNullable(this.idcsAppId);
    }

    /**
     * URL for the location of the IDCS Application (used by IDCS APIs)
     * 
     */
    @Import(name="idcsAppLocationUrl")
    private @Nullable Output<String> idcsAppLocationUrl;

    /**
     * @return URL for the location of the IDCS Application (used by IDCS APIs)
     * 
     */
    public Optional<Output<String>> idcsAppLocationUrl() {
        return Optional.ofNullable(this.idcsAppLocationUrl);
    }

    /**
     * The IDCS application name associated with the instance
     * 
     */
    @Import(name="idcsAppName")
    private @Nullable Output<String> idcsAppName;

    /**
     * @return The IDCS application name associated with the instance
     * 
     */
    public Optional<Output<String>> idcsAppName() {
        return Optional.ofNullable(this.idcsAppName);
    }

    /**
     * The URL used as the primary audience for integration flows in this instance type: string
     * 
     */
    @Import(name="instancePrimaryAudienceUrl")
    private @Nullable Output<String> instancePrimaryAudienceUrl;

    /**
     * @return The URL used as the primary audience for integration flows in this instance type: string
     * 
     */
    public Optional<Output<String>> instancePrimaryAudienceUrl() {
        return Optional.ofNullable(this.instancePrimaryAudienceUrl);
    }

    private IntegrationInstanceIdcsInfoArgs() {}

    private IntegrationInstanceIdcsInfoArgs(IntegrationInstanceIdcsInfoArgs $) {
        this.idcsAppDisplayName = $.idcsAppDisplayName;
        this.idcsAppId = $.idcsAppId;
        this.idcsAppLocationUrl = $.idcsAppLocationUrl;
        this.idcsAppName = $.idcsAppName;
        this.instancePrimaryAudienceUrl = $.instancePrimaryAudienceUrl;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(IntegrationInstanceIdcsInfoArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private IntegrationInstanceIdcsInfoArgs $;

        public Builder() {
            $ = new IntegrationInstanceIdcsInfoArgs();
        }

        public Builder(IntegrationInstanceIdcsInfoArgs defaults) {
            $ = new IntegrationInstanceIdcsInfoArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param idcsAppDisplayName The IDCS application display name associated with the instance
         * 
         * @return builder
         * 
         */
        public Builder idcsAppDisplayName(@Nullable Output<String> idcsAppDisplayName) {
            $.idcsAppDisplayName = idcsAppDisplayName;
            return this;
        }

        /**
         * @param idcsAppDisplayName The IDCS application display name associated with the instance
         * 
         * @return builder
         * 
         */
        public Builder idcsAppDisplayName(String idcsAppDisplayName) {
            return idcsAppDisplayName(Output.of(idcsAppDisplayName));
        }

        /**
         * @param idcsAppId The IDCS application ID associated with the instance
         * 
         * @return builder
         * 
         */
        public Builder idcsAppId(@Nullable Output<String> idcsAppId) {
            $.idcsAppId = idcsAppId;
            return this;
        }

        /**
         * @param idcsAppId The IDCS application ID associated with the instance
         * 
         * @return builder
         * 
         */
        public Builder idcsAppId(String idcsAppId) {
            return idcsAppId(Output.of(idcsAppId));
        }

        /**
         * @param idcsAppLocationUrl URL for the location of the IDCS Application (used by IDCS APIs)
         * 
         * @return builder
         * 
         */
        public Builder idcsAppLocationUrl(@Nullable Output<String> idcsAppLocationUrl) {
            $.idcsAppLocationUrl = idcsAppLocationUrl;
            return this;
        }

        /**
         * @param idcsAppLocationUrl URL for the location of the IDCS Application (used by IDCS APIs)
         * 
         * @return builder
         * 
         */
        public Builder idcsAppLocationUrl(String idcsAppLocationUrl) {
            return idcsAppLocationUrl(Output.of(idcsAppLocationUrl));
        }

        /**
         * @param idcsAppName The IDCS application name associated with the instance
         * 
         * @return builder
         * 
         */
        public Builder idcsAppName(@Nullable Output<String> idcsAppName) {
            $.idcsAppName = idcsAppName;
            return this;
        }

        /**
         * @param idcsAppName The IDCS application name associated with the instance
         * 
         * @return builder
         * 
         */
        public Builder idcsAppName(String idcsAppName) {
            return idcsAppName(Output.of(idcsAppName));
        }

        /**
         * @param instancePrimaryAudienceUrl The URL used as the primary audience for integration flows in this instance type: string
         * 
         * @return builder
         * 
         */
        public Builder instancePrimaryAudienceUrl(@Nullable Output<String> instancePrimaryAudienceUrl) {
            $.instancePrimaryAudienceUrl = instancePrimaryAudienceUrl;
            return this;
        }

        /**
         * @param instancePrimaryAudienceUrl The URL used as the primary audience for integration flows in this instance type: string
         * 
         * @return builder
         * 
         */
        public Builder instancePrimaryAudienceUrl(String instancePrimaryAudienceUrl) {
            return instancePrimaryAudienceUrl(Output.of(instancePrimaryAudienceUrl));
        }

        public IntegrationInstanceIdcsInfoArgs build() {
            return $;
        }
    }

}