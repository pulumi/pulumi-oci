// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Bastion.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class SessionTargetResourceDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final SessionTargetResourceDetailsArgs Empty = new SessionTargetResourceDetailsArgs();

    /**
     * The session type.
     * 
     */
    @Import(name="sessionType", required=true)
    private Output<String> sessionType;

    /**
     * @return The session type.
     * 
     */
    public Output<String> sessionType() {
        return this.sessionType;
    }

    /**
     * The display name of the target Compute instance that the session connects to.
     * 
     */
    @Import(name="targetResourceDisplayName")
    private @Nullable Output<String> targetResourceDisplayName;

    /**
     * @return The display name of the target Compute instance that the session connects to.
     * 
     */
    public Optional<Output<String>> targetResourceDisplayName() {
        return Optional.ofNullable(this.targetResourceDisplayName);
    }

    /**
     * The unique identifier (OCID) of the target resource (a Compute instance, for example) that the session connects to. It&#39;s optional depends on the type of session you want to create.
     * * (Required) For MANAGED_SSH session type, we can only use target_resource_id to create session.
     * * (Optional) For PORT_FORWARDING session type, you must either use target_resource_id or target_resource_private_ip_address
     * 
     */
    @Import(name="targetResourceId")
    private @Nullable Output<String> targetResourceId;

    /**
     * @return The unique identifier (OCID) of the target resource (a Compute instance, for example) that the session connects to. It&#39;s optional depends on the type of session you want to create.
     * * (Required) For MANAGED_SSH session type, we can only use target_resource_id to create session.
     * * (Optional) For PORT_FORWARDING session type, you must either use target_resource_id or target_resource_private_ip_address
     * 
     */
    public Optional<Output<String>> targetResourceId() {
        return Optional.ofNullable(this.targetResourceId);
    }

    /**
     * The name of the user on the target resource operating system that the session uses for the connection.
     * 
     */
    @Import(name="targetResourceOperatingSystemUserName")
    private @Nullable Output<String> targetResourceOperatingSystemUserName;

    /**
     * @return The name of the user on the target resource operating system that the session uses for the connection.
     * 
     */
    public Optional<Output<String>> targetResourceOperatingSystemUserName() {
        return Optional.ofNullable(this.targetResourceOperatingSystemUserName);
    }

    /**
     * The port number to connect to on the target resource.
     * 
     */
    @Import(name="targetResourcePort")
    private @Nullable Output<Integer> targetResourcePort;

    /**
     * @return The port number to connect to on the target resource.
     * 
     */
    public Optional<Output<Integer>> targetResourcePort() {
        return Optional.ofNullable(this.targetResourcePort);
    }

    /**
     * The private IP address of the target resource that the session connects to. For PORT_FORWARDING session type, you must either use target_resource_id or target_resource_private_ip_address
     * 
     */
    @Import(name="targetResourcePrivateIpAddress")
    private @Nullable Output<String> targetResourcePrivateIpAddress;

    /**
     * @return The private IP address of the target resource that the session connects to. For PORT_FORWARDING session type, you must either use target_resource_id or target_resource_private_ip_address
     * 
     */
    public Optional<Output<String>> targetResourcePrivateIpAddress() {
        return Optional.ofNullable(this.targetResourcePrivateIpAddress);
    }

    private SessionTargetResourceDetailsArgs() {}

    private SessionTargetResourceDetailsArgs(SessionTargetResourceDetailsArgs $) {
        this.sessionType = $.sessionType;
        this.targetResourceDisplayName = $.targetResourceDisplayName;
        this.targetResourceId = $.targetResourceId;
        this.targetResourceOperatingSystemUserName = $.targetResourceOperatingSystemUserName;
        this.targetResourcePort = $.targetResourcePort;
        this.targetResourcePrivateIpAddress = $.targetResourcePrivateIpAddress;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(SessionTargetResourceDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private SessionTargetResourceDetailsArgs $;

        public Builder() {
            $ = new SessionTargetResourceDetailsArgs();
        }

        public Builder(SessionTargetResourceDetailsArgs defaults) {
            $ = new SessionTargetResourceDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param sessionType The session type.
         * 
         * @return builder
         * 
         */
        public Builder sessionType(Output<String> sessionType) {
            $.sessionType = sessionType;
            return this;
        }

        /**
         * @param sessionType The session type.
         * 
         * @return builder
         * 
         */
        public Builder sessionType(String sessionType) {
            return sessionType(Output.of(sessionType));
        }

        /**
         * @param targetResourceDisplayName The display name of the target Compute instance that the session connects to.
         * 
         * @return builder
         * 
         */
        public Builder targetResourceDisplayName(@Nullable Output<String> targetResourceDisplayName) {
            $.targetResourceDisplayName = targetResourceDisplayName;
            return this;
        }

        /**
         * @param targetResourceDisplayName The display name of the target Compute instance that the session connects to.
         * 
         * @return builder
         * 
         */
        public Builder targetResourceDisplayName(String targetResourceDisplayName) {
            return targetResourceDisplayName(Output.of(targetResourceDisplayName));
        }

        /**
         * @param targetResourceId The unique identifier (OCID) of the target resource (a Compute instance, for example) that the session connects to. It&#39;s optional depends on the type of session you want to create.
         * * (Required) For MANAGED_SSH session type, we can only use target_resource_id to create session.
         * * (Optional) For PORT_FORWARDING session type, you must either use target_resource_id or target_resource_private_ip_address
         * 
         * @return builder
         * 
         */
        public Builder targetResourceId(@Nullable Output<String> targetResourceId) {
            $.targetResourceId = targetResourceId;
            return this;
        }

        /**
         * @param targetResourceId The unique identifier (OCID) of the target resource (a Compute instance, for example) that the session connects to. It&#39;s optional depends on the type of session you want to create.
         * * (Required) For MANAGED_SSH session type, we can only use target_resource_id to create session.
         * * (Optional) For PORT_FORWARDING session type, you must either use target_resource_id or target_resource_private_ip_address
         * 
         * @return builder
         * 
         */
        public Builder targetResourceId(String targetResourceId) {
            return targetResourceId(Output.of(targetResourceId));
        }

        /**
         * @param targetResourceOperatingSystemUserName The name of the user on the target resource operating system that the session uses for the connection.
         * 
         * @return builder
         * 
         */
        public Builder targetResourceOperatingSystemUserName(@Nullable Output<String> targetResourceOperatingSystemUserName) {
            $.targetResourceOperatingSystemUserName = targetResourceOperatingSystemUserName;
            return this;
        }

        /**
         * @param targetResourceOperatingSystemUserName The name of the user on the target resource operating system that the session uses for the connection.
         * 
         * @return builder
         * 
         */
        public Builder targetResourceOperatingSystemUserName(String targetResourceOperatingSystemUserName) {
            return targetResourceOperatingSystemUserName(Output.of(targetResourceOperatingSystemUserName));
        }

        /**
         * @param targetResourcePort The port number to connect to on the target resource.
         * 
         * @return builder
         * 
         */
        public Builder targetResourcePort(@Nullable Output<Integer> targetResourcePort) {
            $.targetResourcePort = targetResourcePort;
            return this;
        }

        /**
         * @param targetResourcePort The port number to connect to on the target resource.
         * 
         * @return builder
         * 
         */
        public Builder targetResourcePort(Integer targetResourcePort) {
            return targetResourcePort(Output.of(targetResourcePort));
        }

        /**
         * @param targetResourcePrivateIpAddress The private IP address of the target resource that the session connects to. For PORT_FORWARDING session type, you must either use target_resource_id or target_resource_private_ip_address
         * 
         * @return builder
         * 
         */
        public Builder targetResourcePrivateIpAddress(@Nullable Output<String> targetResourcePrivateIpAddress) {
            $.targetResourcePrivateIpAddress = targetResourcePrivateIpAddress;
            return this;
        }

        /**
         * @param targetResourcePrivateIpAddress The private IP address of the target resource that the session connects to. For PORT_FORWARDING session type, you must either use target_resource_id or target_resource_private_ip_address
         * 
         * @return builder
         * 
         */
        public Builder targetResourcePrivateIpAddress(String targetResourcePrivateIpAddress) {
            return targetResourcePrivateIpAddress(Output.of(targetResourcePrivateIpAddress));
        }

        public SessionTargetResourceDetailsArgs build() {
            $.sessionType = Objects.requireNonNull($.sessionType, "expected parameter 'sessionType' to be non-null");
            return $;
        }
    }

}
