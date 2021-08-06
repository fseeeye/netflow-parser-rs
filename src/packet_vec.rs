use crate::errors::ParseError;
use crate::layer::{Layer, FatLayer};
use crate::layer_type::LayerType;
use crate::ParsersMap;


#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct VecPacketOptions {
    stop: Option<LayerType>
}

impl VecPacketOptions {
    pub fn new() -> Self {
        Self {
            stop: None,
        }
    }
}

#[derive(Debug)]
pub struct VecPacket<'a> {
    input: &'a [u8],
    layers: Vec<FatLayer<'a>>,
    next: Option<LayerType>,
    options: VecPacketOptions,
}

impl<'a> VecPacket<'a> {
    pub fn new(input: &'a [u8], options: VecPacketOptions) -> Self {
        Self {
            input,
            layers: vec!(),
            next: Some(LayerType::Ethernet),
            options,
        }
    }

    // Parse packet until:
    // - self.next is None
    // - arrive `options.stop` layer
    pub fn parse(&mut self, parsers_map: &ParsersMap) {
        loop {
            // If self.next is None, break loop.
            if let Some(old_next) = self.next {
                // Get next parser from parsers_map
                if let Some(parser) = parsers_map.get(&old_next) {
                    match parser(&self.input) {
                        Ok((input, (nlayer, new_next))) => {
                            self.input = input;
                            self.push_layer(FatLayer::new(old_next.clone(), nlayer));
                            self.next = new_next; // Tips: next layer might be `Unknow / NomPeek`
                        },
                        // Error occurred: parsing next layer. update self.next to ParseError::Parsing
                        Err(_) => {
                            // eprintln!("[!] Parsing Error `{:?}` at Layer `{:?}`", e, old_next);
                            // break;
                            self.next = Some(LayerType::Error(ParseError::ParsingHeader));
                        },
                    };
                } else { // Error occurred: Can't find parser correspond to self.next
                    // eprintln!("[!] Don't register any parser for Layer `{:?}`", old_next);
                    // break;
                    self.next = Some(LayerType::Error(ParseError::UnregisteredParser));
                }
            } else {
                break;
            }
        }
    }

    pub fn get_layer(&self, layer_type: LayerType) -> Option<&Layer> {
        for layer in self.layers.iter() {
            if layer_type == layer.get_type() {
                return Some(layer.get_layer())
            }
        }
        None
    }

    pub fn get_layers(&self) -> &Vec<FatLayer<'a>> {
        &self.layers
    }

    fn push_layer(&mut self, flayer: FatLayer<'a>) {
        self.layers.push(flayer)
    }
}