// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ContainerEngine.inputs.ContainerInstanceContainerHealthCheckHeaderArgs;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ContainerInstanceContainerHealthCheckArgs extends com.pulumi.resources.ResourceArgs {

    public static final ContainerInstanceContainerHealthCheckArgs Empty = new ContainerInstanceContainerHealthCheckArgs();

    /**
     * The action will be triggered when the container health check fails. There are two types of action: KILL or NONE. The default action is KILL. If failure action is KILL, the container will be subject to the container restart policy.
     * 
     */
    @Import(name="failureAction")
    private @Nullable Output<String> failureAction;

    /**
     * @return The action will be triggered when the container health check fails. There are two types of action: KILL or NONE. The default action is KILL. If failure action is KILL, the container will be subject to the container restart policy.
     * 
     */
    public Optional<Output<String>> failureAction() {
        return Optional.ofNullable(this.failureAction);
    }

    /**
     * Number of consecutive failures at which we consider the check failed.
     * 
     */
    @Import(name="failureThreshold")
    private @Nullable Output<Integer> failureThreshold;

    /**
     * @return Number of consecutive failures at which we consider the check failed.
     * 
     */
    public Optional<Output<Integer>> failureThreshold() {
        return Optional.ofNullable(this.failureThreshold);
    }

    /**
     * Container health check HTTP headers.
     * 
     */
    @Import(name="headers")
    private @Nullable Output<List<ContainerInstanceContainerHealthCheckHeaderArgs>> headers;

    /**
     * @return Container health check HTTP headers.
     * 
     */
    public Optional<Output<List<ContainerInstanceContainerHealthCheckHeaderArgs>>> headers() {
        return Optional.ofNullable(this.headers);
    }

    /**
     * Container health check type.
     * 
     */
    @Import(name="healthCheckType", required=true)
    private Output<String> healthCheckType;

    /**
     * @return Container health check type.
     * 
     */
    public Output<String> healthCheckType() {
        return this.healthCheckType;
    }

    /**
     * The initial delay in seconds before start checking container health status.
     * 
     */
    @Import(name="initialDelayInSeconds")
    private @Nullable Output<Integer> initialDelayInSeconds;

    /**
     * @return The initial delay in seconds before start checking container health status.
     * 
     */
    public Optional<Output<Integer>> initialDelayInSeconds() {
        return Optional.ofNullable(this.initialDelayInSeconds);
    }

    /**
     * Number of seconds between two consecutive runs for checking container health.
     * 
     */
    @Import(name="intervalInSeconds")
    private @Nullable Output<Integer> intervalInSeconds;

    /**
     * @return Number of seconds between two consecutive runs for checking container health.
     * 
     */
    public Optional<Output<Integer>> intervalInSeconds() {
        return Optional.ofNullable(this.intervalInSeconds);
    }

    /**
     * Health check name.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return Health check name.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * Container health check HTTP path.
     * 
     */
    @Import(name="path")
    private @Nullable Output<String> path;

    /**
     * @return Container health check HTTP path.
     * 
     */
    public Optional<Output<String>> path() {
        return Optional.ofNullable(this.path);
    }

    /**
     * Container health check HTTP port.
     * 
     */
    @Import(name="port")
    private @Nullable Output<Integer> port;

    /**
     * @return Container health check HTTP port.
     * 
     */
    public Optional<Output<Integer>> port() {
        return Optional.ofNullable(this.port);
    }

    @Import(name="status")
    private @Nullable Output<String> status;

    public Optional<Output<String>> status() {
        return Optional.ofNullable(this.status);
    }

    @Import(name="statusDetails")
    private @Nullable Output<String> statusDetails;

    public Optional<Output<String>> statusDetails() {
        return Optional.ofNullable(this.statusDetails);
    }

    /**
     * Number of consecutive successes at which we consider the check succeeded again after it was in failure state.
     * 
     */
    @Import(name="successThreshold")
    private @Nullable Output<Integer> successThreshold;

    /**
     * @return Number of consecutive successes at which we consider the check succeeded again after it was in failure state.
     * 
     */
    public Optional<Output<Integer>> successThreshold() {
        return Optional.ofNullable(this.successThreshold);
    }

    /**
     * Length of waiting time in seconds before marking health check failed.
     * 
     */
    @Import(name="timeoutInSeconds")
    private @Nullable Output<Integer> timeoutInSeconds;

    /**
     * @return Length of waiting time in seconds before marking health check failed.
     * 
     */
    public Optional<Output<Integer>> timeoutInSeconds() {
        return Optional.ofNullable(this.timeoutInSeconds);
    }

    private ContainerInstanceContainerHealthCheckArgs() {}

    private ContainerInstanceContainerHealthCheckArgs(ContainerInstanceContainerHealthCheckArgs $) {
        this.failureAction = $.failureAction;
        this.failureThreshold = $.failureThreshold;
        this.headers = $.headers;
        this.healthCheckType = $.healthCheckType;
        this.initialDelayInSeconds = $.initialDelayInSeconds;
        this.intervalInSeconds = $.intervalInSeconds;
        this.name = $.name;
        this.path = $.path;
        this.port = $.port;
        this.status = $.status;
        this.statusDetails = $.statusDetails;
        this.successThreshold = $.successThreshold;
        this.timeoutInSeconds = $.timeoutInSeconds;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ContainerInstanceContainerHealthCheckArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ContainerInstanceContainerHealthCheckArgs $;

        public Builder() {
            $ = new ContainerInstanceContainerHealthCheckArgs();
        }

        public Builder(ContainerInstanceContainerHealthCheckArgs defaults) {
            $ = new ContainerInstanceContainerHealthCheckArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param failureAction The action will be triggered when the container health check fails. There are two types of action: KILL or NONE. The default action is KILL. If failure action is KILL, the container will be subject to the container restart policy.
         * 
         * @return builder
         * 
         */
        public Builder failureAction(@Nullable Output<String> failureAction) {
            $.failureAction = failureAction;
            return this;
        }

        /**
         * @param failureAction The action will be triggered when the container health check fails. There are two types of action: KILL or NONE. The default action is KILL. If failure action is KILL, the container will be subject to the container restart policy.
         * 
         * @return builder
         * 
         */
        public Builder failureAction(String failureAction) {
            return failureAction(Output.of(failureAction));
        }

        /**
         * @param failureThreshold Number of consecutive failures at which we consider the check failed.
         * 
         * @return builder
         * 
         */
        public Builder failureThreshold(@Nullable Output<Integer> failureThreshold) {
            $.failureThreshold = failureThreshold;
            return this;
        }

        /**
         * @param failureThreshold Number of consecutive failures at which we consider the check failed.
         * 
         * @return builder
         * 
         */
        public Builder failureThreshold(Integer failureThreshold) {
            return failureThreshold(Output.of(failureThreshold));
        }

        /**
         * @param headers Container health check HTTP headers.
         * 
         * @return builder
         * 
         */
        public Builder headers(@Nullable Output<List<ContainerInstanceContainerHealthCheckHeaderArgs>> headers) {
            $.headers = headers;
            return this;
        }

        /**
         * @param headers Container health check HTTP headers.
         * 
         * @return builder
         * 
         */
        public Builder headers(List<ContainerInstanceContainerHealthCheckHeaderArgs> headers) {
            return headers(Output.of(headers));
        }

        /**
         * @param headers Container health check HTTP headers.
         * 
         * @return builder
         * 
         */
        public Builder headers(ContainerInstanceContainerHealthCheckHeaderArgs... headers) {
            return headers(List.of(headers));
        }

        /**
         * @param healthCheckType Container health check type.
         * 
         * @return builder
         * 
         */
        public Builder healthCheckType(Output<String> healthCheckType) {
            $.healthCheckType = healthCheckType;
            return this;
        }

        /**
         * @param healthCheckType Container health check type.
         * 
         * @return builder
         * 
         */
        public Builder healthCheckType(String healthCheckType) {
            return healthCheckType(Output.of(healthCheckType));
        }

        /**
         * @param initialDelayInSeconds The initial delay in seconds before start checking container health status.
         * 
         * @return builder
         * 
         */
        public Builder initialDelayInSeconds(@Nullable Output<Integer> initialDelayInSeconds) {
            $.initialDelayInSeconds = initialDelayInSeconds;
            return this;
        }

        /**
         * @param initialDelayInSeconds The initial delay in seconds before start checking container health status.
         * 
         * @return builder
         * 
         */
        public Builder initialDelayInSeconds(Integer initialDelayInSeconds) {
            return initialDelayInSeconds(Output.of(initialDelayInSeconds));
        }

        /**
         * @param intervalInSeconds Number of seconds between two consecutive runs for checking container health.
         * 
         * @return builder
         * 
         */
        public Builder intervalInSeconds(@Nullable Output<Integer> intervalInSeconds) {
            $.intervalInSeconds = intervalInSeconds;
            return this;
        }

        /**
         * @param intervalInSeconds Number of seconds between two consecutive runs for checking container health.
         * 
         * @return builder
         * 
         */
        public Builder intervalInSeconds(Integer intervalInSeconds) {
            return intervalInSeconds(Output.of(intervalInSeconds));
        }

        /**
         * @param name Health check name.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name Health check name.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param path Container health check HTTP path.
         * 
         * @return builder
         * 
         */
        public Builder path(@Nullable Output<String> path) {
            $.path = path;
            return this;
        }

        /**
         * @param path Container health check HTTP path.
         * 
         * @return builder
         * 
         */
        public Builder path(String path) {
            return path(Output.of(path));
        }

        /**
         * @param port Container health check HTTP port.
         * 
         * @return builder
         * 
         */
        public Builder port(@Nullable Output<Integer> port) {
            $.port = port;
            return this;
        }

        /**
         * @param port Container health check HTTP port.
         * 
         * @return builder
         * 
         */
        public Builder port(Integer port) {
            return port(Output.of(port));
        }

        public Builder status(@Nullable Output<String> status) {
            $.status = status;
            return this;
        }

        public Builder status(String status) {
            return status(Output.of(status));
        }

        public Builder statusDetails(@Nullable Output<String> statusDetails) {
            $.statusDetails = statusDetails;
            return this;
        }

        public Builder statusDetails(String statusDetails) {
            return statusDetails(Output.of(statusDetails));
        }

        /**
         * @param successThreshold Number of consecutive successes at which we consider the check succeeded again after it was in failure state.
         * 
         * @return builder
         * 
         */
        public Builder successThreshold(@Nullable Output<Integer> successThreshold) {
            $.successThreshold = successThreshold;
            return this;
        }

        /**
         * @param successThreshold Number of consecutive successes at which we consider the check succeeded again after it was in failure state.
         * 
         * @return builder
         * 
         */
        public Builder successThreshold(Integer successThreshold) {
            return successThreshold(Output.of(successThreshold));
        }

        /**
         * @param timeoutInSeconds Length of waiting time in seconds before marking health check failed.
         * 
         * @return builder
         * 
         */
        public Builder timeoutInSeconds(@Nullable Output<Integer> timeoutInSeconds) {
            $.timeoutInSeconds = timeoutInSeconds;
            return this;
        }

        /**
         * @param timeoutInSeconds Length of waiting time in seconds before marking health check failed.
         * 
         * @return builder
         * 
         */
        public Builder timeoutInSeconds(Integer timeoutInSeconds) {
            return timeoutInSeconds(Output.of(timeoutInSeconds));
        }

        public ContainerInstanceContainerHealthCheckArgs build() {
            if ($.healthCheckType == null) {
                throw new MissingRequiredPropertyException("ContainerInstanceContainerHealthCheckArgs", "healthCheckType");
            }
            return $;
        }
    }

}
