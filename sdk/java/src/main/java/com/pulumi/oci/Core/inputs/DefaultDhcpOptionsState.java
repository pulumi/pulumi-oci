// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.DefaultDhcpOptionsOptionArgs;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DefaultDhcpOptionsState extends com.pulumi.resources.ResourceArgs {

    public static final DefaultDhcpOptionsState Empty = new DefaultDhcpOptionsState();

    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="domainNameType")
    private @Nullable Output<String> domainNameType;

    public Optional<Output<String>> domainNameType() {
        return Optional.ofNullable(this.domainNameType);
    }

    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    @Import(name="manageDefaultResourceId")
    private @Nullable Output<String> manageDefaultResourceId;

    public Optional<Output<String>> manageDefaultResourceId() {
        return Optional.ofNullable(this.manageDefaultResourceId);
    }

    @Import(name="options")
    private @Nullable Output<List<DefaultDhcpOptionsOptionArgs>> options;

    public Optional<Output<List<DefaultDhcpOptionsOptionArgs>>> options() {
        return Optional.ofNullable(this.options);
    }

    @Import(name="state")
    private @Nullable Output<String> state;

    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    private DefaultDhcpOptionsState() {}

    private DefaultDhcpOptionsState(DefaultDhcpOptionsState $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.domainNameType = $.domainNameType;
        this.freeformTags = $.freeformTags;
        this.manageDefaultResourceId = $.manageDefaultResourceId;
        this.options = $.options;
        this.state = $.state;
        this.timeCreated = $.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DefaultDhcpOptionsState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DefaultDhcpOptionsState $;

        public Builder() {
            $ = new DefaultDhcpOptionsState();
        }

        public Builder(DefaultDhcpOptionsState defaults) {
            $ = new DefaultDhcpOptionsState(Objects.requireNonNull(defaults));
        }

        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder domainNameType(@Nullable Output<String> domainNameType) {
            $.domainNameType = domainNameType;
            return this;
        }

        public Builder domainNameType(String domainNameType) {
            return domainNameType(Output.of(domainNameType));
        }

        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        public Builder manageDefaultResourceId(@Nullable Output<String> manageDefaultResourceId) {
            $.manageDefaultResourceId = manageDefaultResourceId;
            return this;
        }

        public Builder manageDefaultResourceId(String manageDefaultResourceId) {
            return manageDefaultResourceId(Output.of(manageDefaultResourceId));
        }

        public Builder options(@Nullable Output<List<DefaultDhcpOptionsOptionArgs>> options) {
            $.options = options;
            return this;
        }

        public Builder options(List<DefaultDhcpOptionsOptionArgs> options) {
            return options(Output.of(options));
        }

        public Builder options(DefaultDhcpOptionsOptionArgs... options) {
            return options(List.of(options));
        }

        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        public Builder state(String state) {
            return state(Output.of(state));
        }

        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        public DefaultDhcpOptionsState build() {
            return $;
        }
    }

}
