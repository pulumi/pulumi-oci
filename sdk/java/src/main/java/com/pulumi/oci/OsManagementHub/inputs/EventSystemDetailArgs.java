// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class EventSystemDetailArgs extends com.pulumi.resources.ResourceArgs {

    public static final EventSystemDetailArgs Empty = new EventSystemDetailArgs();

    /**
     * Architecture type.
     * 
     */
    @Import(name="architecture")
    private @Nullable Output<String> architecture;

    /**
     * @return Architecture type.
     * 
     */
    public Optional<Output<String>> architecture() {
        return Optional.ofNullable(this.architecture);
    }

    /**
     * Version of the Ksplice effective kernel.
     * 
     */
    @Import(name="kspliceEffectiveKernelVersion")
    private @Nullable Output<String> kspliceEffectiveKernelVersion;

    /**
     * @return Version of the Ksplice effective kernel.
     * 
     */
    public Optional<Output<String>> kspliceEffectiveKernelVersion() {
        return Optional.ofNullable(this.kspliceEffectiveKernelVersion);
    }

    /**
     * Operating system type.
     * 
     */
    @Import(name="osFamily")
    private @Nullable Output<String> osFamily;

    /**
     * @return Operating system type.
     * 
     */
    public Optional<Output<String>> osFamily() {
        return Optional.ofNullable(this.osFamily);
    }

    /**
     * Release of the kernel.
     * 
     */
    @Import(name="osKernelRelease")
    private @Nullable Output<String> osKernelRelease;

    /**
     * @return Release of the kernel.
     * 
     */
    public Optional<Output<String>> osKernelRelease() {
        return Optional.ofNullable(this.osKernelRelease);
    }

    /**
     * Version of the kernel.
     * 
     */
    @Import(name="osKernelVersion")
    private @Nullable Output<String> osKernelVersion;

    /**
     * @return Version of the kernel.
     * 
     */
    public Optional<Output<String>> osKernelVersion() {
        return Optional.ofNullable(this.osKernelVersion);
    }

    /**
     * Name of the operating system.
     * 
     */
    @Import(name="osName")
    private @Nullable Output<String> osName;

    /**
     * @return Name of the operating system.
     * 
     */
    public Optional<Output<String>> osName() {
        return Optional.ofNullable(this.osName);
    }

    /**
     * Version of the operating system.
     * 
     */
    @Import(name="osSystemVersion")
    private @Nullable Output<String> osSystemVersion;

    /**
     * @return Version of the operating system.
     * 
     */
    public Optional<Output<String>> osSystemVersion() {
        return Optional.ofNullable(this.osSystemVersion);
    }

    private EventSystemDetailArgs() {}

    private EventSystemDetailArgs(EventSystemDetailArgs $) {
        this.architecture = $.architecture;
        this.kspliceEffectiveKernelVersion = $.kspliceEffectiveKernelVersion;
        this.osFamily = $.osFamily;
        this.osKernelRelease = $.osKernelRelease;
        this.osKernelVersion = $.osKernelVersion;
        this.osName = $.osName;
        this.osSystemVersion = $.osSystemVersion;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(EventSystemDetailArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private EventSystemDetailArgs $;

        public Builder() {
            $ = new EventSystemDetailArgs();
        }

        public Builder(EventSystemDetailArgs defaults) {
            $ = new EventSystemDetailArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param architecture Architecture type.
         * 
         * @return builder
         * 
         */
        public Builder architecture(@Nullable Output<String> architecture) {
            $.architecture = architecture;
            return this;
        }

        /**
         * @param architecture Architecture type.
         * 
         * @return builder
         * 
         */
        public Builder architecture(String architecture) {
            return architecture(Output.of(architecture));
        }

        /**
         * @param kspliceEffectiveKernelVersion Version of the Ksplice effective kernel.
         * 
         * @return builder
         * 
         */
        public Builder kspliceEffectiveKernelVersion(@Nullable Output<String> kspliceEffectiveKernelVersion) {
            $.kspliceEffectiveKernelVersion = kspliceEffectiveKernelVersion;
            return this;
        }

        /**
         * @param kspliceEffectiveKernelVersion Version of the Ksplice effective kernel.
         * 
         * @return builder
         * 
         */
        public Builder kspliceEffectiveKernelVersion(String kspliceEffectiveKernelVersion) {
            return kspliceEffectiveKernelVersion(Output.of(kspliceEffectiveKernelVersion));
        }

        /**
         * @param osFamily Operating system type.
         * 
         * @return builder
         * 
         */
        public Builder osFamily(@Nullable Output<String> osFamily) {
            $.osFamily = osFamily;
            return this;
        }

        /**
         * @param osFamily Operating system type.
         * 
         * @return builder
         * 
         */
        public Builder osFamily(String osFamily) {
            return osFamily(Output.of(osFamily));
        }

        /**
         * @param osKernelRelease Release of the kernel.
         * 
         * @return builder
         * 
         */
        public Builder osKernelRelease(@Nullable Output<String> osKernelRelease) {
            $.osKernelRelease = osKernelRelease;
            return this;
        }

        /**
         * @param osKernelRelease Release of the kernel.
         * 
         * @return builder
         * 
         */
        public Builder osKernelRelease(String osKernelRelease) {
            return osKernelRelease(Output.of(osKernelRelease));
        }

        /**
         * @param osKernelVersion Version of the kernel.
         * 
         * @return builder
         * 
         */
        public Builder osKernelVersion(@Nullable Output<String> osKernelVersion) {
            $.osKernelVersion = osKernelVersion;
            return this;
        }

        /**
         * @param osKernelVersion Version of the kernel.
         * 
         * @return builder
         * 
         */
        public Builder osKernelVersion(String osKernelVersion) {
            return osKernelVersion(Output.of(osKernelVersion));
        }

        /**
         * @param osName Name of the operating system.
         * 
         * @return builder
         * 
         */
        public Builder osName(@Nullable Output<String> osName) {
            $.osName = osName;
            return this;
        }

        /**
         * @param osName Name of the operating system.
         * 
         * @return builder
         * 
         */
        public Builder osName(String osName) {
            return osName(Output.of(osName));
        }

        /**
         * @param osSystemVersion Version of the operating system.
         * 
         * @return builder
         * 
         */
        public Builder osSystemVersion(@Nullable Output<String> osSystemVersion) {
            $.osSystemVersion = osSystemVersion;
            return this;
        }

        /**
         * @param osSystemVersion Version of the operating system.
         * 
         * @return builder
         * 
         */
        public Builder osSystemVersion(String osSystemVersion) {
            return osSystemVersion(Output.of(osSystemVersion));
        }

        public EventSystemDetailArgs build() {
            return $;
        }
    }

}
