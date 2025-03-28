// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Desktops.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDesktopPoolsDesktopPoolCollectionItemDevicePolicy {
    /**
     * @return The audio mode. NONE: No access to the local audio devices is permitted. TODESKTOP: The user may record audio on their desktop.  FROMDESKTOP: The user may play audio on their desktop. FULL: The user may play and record audio on their desktop.
     * 
     */
    private String audioMode;
    /**
     * @return The client local drive access mode. NONE: No access to local drives permitted. READONLY: The user may read from local drives on their desktop. FULL: The user may read from and write to their local drives on their desktop.
     * 
     */
    private String cdmMode;
    /**
     * @return The clipboard mode. NONE: No access to the local clipboard is permitted. TODESKTOP: The clipboard can be used to transfer data to the desktop only.  FROMDESKTOP: The clipboard can be used to transfer data from the desktop only. FULL: The clipboard can be used to transfer data to and from the desktop.
     * 
     */
    private String clipboardMode;
    /**
     * @return Indicates whether the display is enabled.
     * 
     */
    private Boolean isDisplayEnabled;
    /**
     * @return Indicates whether the keyboard is enabled.
     * 
     */
    private Boolean isKeyboardEnabled;
    /**
     * @return Indicates whether the pointer is enabled.
     * 
     */
    private Boolean isPointerEnabled;
    /**
     * @return Indicates whether printing is enabled.
     * 
     */
    private Boolean isPrintingEnabled;

    private GetDesktopPoolsDesktopPoolCollectionItemDevicePolicy() {}
    /**
     * @return The audio mode. NONE: No access to the local audio devices is permitted. TODESKTOP: The user may record audio on their desktop.  FROMDESKTOP: The user may play audio on their desktop. FULL: The user may play and record audio on their desktop.
     * 
     */
    public String audioMode() {
        return this.audioMode;
    }
    /**
     * @return The client local drive access mode. NONE: No access to local drives permitted. READONLY: The user may read from local drives on their desktop. FULL: The user may read from and write to their local drives on their desktop.
     * 
     */
    public String cdmMode() {
        return this.cdmMode;
    }
    /**
     * @return The clipboard mode. NONE: No access to the local clipboard is permitted. TODESKTOP: The clipboard can be used to transfer data to the desktop only.  FROMDESKTOP: The clipboard can be used to transfer data from the desktop only. FULL: The clipboard can be used to transfer data to and from the desktop.
     * 
     */
    public String clipboardMode() {
        return this.clipboardMode;
    }
    /**
     * @return Indicates whether the display is enabled.
     * 
     */
    public Boolean isDisplayEnabled() {
        return this.isDisplayEnabled;
    }
    /**
     * @return Indicates whether the keyboard is enabled.
     * 
     */
    public Boolean isKeyboardEnabled() {
        return this.isKeyboardEnabled;
    }
    /**
     * @return Indicates whether the pointer is enabled.
     * 
     */
    public Boolean isPointerEnabled() {
        return this.isPointerEnabled;
    }
    /**
     * @return Indicates whether printing is enabled.
     * 
     */
    public Boolean isPrintingEnabled() {
        return this.isPrintingEnabled;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDesktopPoolsDesktopPoolCollectionItemDevicePolicy defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String audioMode;
        private String cdmMode;
        private String clipboardMode;
        private Boolean isDisplayEnabled;
        private Boolean isKeyboardEnabled;
        private Boolean isPointerEnabled;
        private Boolean isPrintingEnabled;
        public Builder() {}
        public Builder(GetDesktopPoolsDesktopPoolCollectionItemDevicePolicy defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.audioMode = defaults.audioMode;
    	      this.cdmMode = defaults.cdmMode;
    	      this.clipboardMode = defaults.clipboardMode;
    	      this.isDisplayEnabled = defaults.isDisplayEnabled;
    	      this.isKeyboardEnabled = defaults.isKeyboardEnabled;
    	      this.isPointerEnabled = defaults.isPointerEnabled;
    	      this.isPrintingEnabled = defaults.isPrintingEnabled;
        }

        @CustomType.Setter
        public Builder audioMode(String audioMode) {
            if (audioMode == null) {
              throw new MissingRequiredPropertyException("GetDesktopPoolsDesktopPoolCollectionItemDevicePolicy", "audioMode");
            }
            this.audioMode = audioMode;
            return this;
        }
        @CustomType.Setter
        public Builder cdmMode(String cdmMode) {
            if (cdmMode == null) {
              throw new MissingRequiredPropertyException("GetDesktopPoolsDesktopPoolCollectionItemDevicePolicy", "cdmMode");
            }
            this.cdmMode = cdmMode;
            return this;
        }
        @CustomType.Setter
        public Builder clipboardMode(String clipboardMode) {
            if (clipboardMode == null) {
              throw new MissingRequiredPropertyException("GetDesktopPoolsDesktopPoolCollectionItemDevicePolicy", "clipboardMode");
            }
            this.clipboardMode = clipboardMode;
            return this;
        }
        @CustomType.Setter
        public Builder isDisplayEnabled(Boolean isDisplayEnabled) {
            if (isDisplayEnabled == null) {
              throw new MissingRequiredPropertyException("GetDesktopPoolsDesktopPoolCollectionItemDevicePolicy", "isDisplayEnabled");
            }
            this.isDisplayEnabled = isDisplayEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder isKeyboardEnabled(Boolean isKeyboardEnabled) {
            if (isKeyboardEnabled == null) {
              throw new MissingRequiredPropertyException("GetDesktopPoolsDesktopPoolCollectionItemDevicePolicy", "isKeyboardEnabled");
            }
            this.isKeyboardEnabled = isKeyboardEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder isPointerEnabled(Boolean isPointerEnabled) {
            if (isPointerEnabled == null) {
              throw new MissingRequiredPropertyException("GetDesktopPoolsDesktopPoolCollectionItemDevicePolicy", "isPointerEnabled");
            }
            this.isPointerEnabled = isPointerEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder isPrintingEnabled(Boolean isPrintingEnabled) {
            if (isPrintingEnabled == null) {
              throw new MissingRequiredPropertyException("GetDesktopPoolsDesktopPoolCollectionItemDevicePolicy", "isPrintingEnabled");
            }
            this.isPrintingEnabled = isPrintingEnabled;
            return this;
        }
        public GetDesktopPoolsDesktopPoolCollectionItemDevicePolicy build() {
            final var _resultValue = new GetDesktopPoolsDesktopPoolCollectionItemDevicePolicy();
            _resultValue.audioMode = audioMode;
            _resultValue.cdmMode = cdmMode;
            _resultValue.clipboardMode = clipboardMode;
            _resultValue.isDisplayEnabled = isDisplayEnabled;
            _resultValue.isKeyboardEnabled = isKeyboardEnabled;
            _resultValue.isPointerEnabled = isPointerEnabled;
            _resultValue.isPrintingEnabled = isPrintingEnabled;
            return _resultValue;
        }
    }
}
