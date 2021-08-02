use crate::layer_type::LayerType;

pub trait Header {
    // fn get_type(&self) -> LayerType;
    fn get_payload(&self) -> Option<LayerType>;
}